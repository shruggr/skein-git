//! A git packfile, read whole (gitformat-pack(5)): "PACK", version 2 or 3,
//! the object count, the objects, and the SHA-1 of all that as a trailer.
//! Each object is a type and size header then zlib data; a delta (`ofs`: a
//! base earlier in the pack by offset, `ref`: a base by id) is applied to
//! its base to give the object. Every object comes out whole, as git hashes
//! it: "<type> <size>\0<content>", its id the SHA-1 of those bytes — the
//! bytes a skein stores under CIDv1(git-raw, sha1) of that id. Nothing here
//! trusts the pack: ids are computed, never read from it.
//!
//! The pack is not kept: only the objects a caller takes from it are.
const std = @import("std");
const flate = std.compress.flate;
const Sha1 = std.crypto.hash.Sha1;

const Allocator = std.mem.Allocator;

pub const Kind = enum(u3) {
    commit = 1,
    tree = 2,
    blob = 3,
    tag = 4,

    pub fn name(k: Kind) []const u8 {
        return @tagName(k);
    }
};

pub const Object = struct {
    kind: Kind,
    id: [20]u8,
    /// The whole object: "<kind> <size>\0" ++ content.
    object: []const u8,
    /// Its content (a slice of `object`).
    content: []const u8,
};

pub const Error = error{ BadPack, OutOfMemory };

/// Limits on what a pack may unpack to: the sum of its objects' sizes, and
/// how many objects.
pub const Limits = struct { bytes: usize, objects: usize };

pub const Pack = struct {
    objects: []const Object,
    by_id: std.AutoHashMapUnmanaged([20]u8, u32),

    pub fn get(p: *const Pack, id: [20]u8) ?Object {
        const i = p.by_id.get(id) orelse return null;
        return p.objects[i];
    }
};

const Raw = struct {
    /// The offset of the entry in the pack.
    at: usize,
    /// 1-4 an object, 6 ofs-delta, 7 ref-delta.
    type: u3,
    base_at: usize = 0,
    base_id: [20]u8 = undefined,
    data: []const u8,
};

/// Read a whole pack. Refusals set `why`.
pub fn read(a: Allocator, pack: []const u8, limits: Limits, why: *[]const u8) Error!Pack {
    if (pack.len < 32 or !std.mem.eql(u8, pack[0..4], "PACK")) return bad(why, "not a pack");
    const version = std.mem.readInt(u32, pack[4..8], .big);
    if (version != 2 and version != 3) return bad(why, "a pack version other than 2 or 3");
    const count = std.mem.readInt(u32, pack[8..12], .big);
    if (count > limits.objects) return bad(why, "the pack has more objects than allowed");
    const body = pack[0 .. pack.len - 20];
    var sum: [20]u8 = undefined;
    Sha1.hash(body, &sum, .{});
    if (!std.mem.eql(u8, &sum, pack[pack.len - 20 ..])) return bad(why, "the pack's trailer is not its SHA-1: corrupt");

    const raws = try a.alloc(Raw, count);
    var at_index: std.AutoHashMapUnmanaged(usize, u32) = .empty;
    try at_index.ensureTotalCapacity(a, count);
    var total: usize = 0;
    var pos: usize = 12;
    const window = try a.alloc(u8, flate.max_window_len);
    for (raws, 0..) |*r, i| {
        const at = pos;
        if (pos >= body.len) return bad(why, "the pack ends before its objects do");
        var c = body[pos];
        pos += 1;
        const ty: u3 = @intCast((c >> 4) & 7);
        var size: u64 = c & 15;
        var shift: u6 = 4;
        while (c & 0x80 != 0) {
            if (pos >= body.len or shift > 57) return bad(why, "a bad object header");
            c = body[pos];
            pos += 1;
            size |= @as(u64, c & 0x7f) << shift;
            shift += 7;
        }
        r.* = .{ .at = at, .type = ty, .data = undefined };
        switch (ty) {
            1, 2, 3, 4 => {},
            6 => {
                if (pos >= body.len) return bad(why, "a bad delta offset");
                c = body[pos];
                pos += 1;
                var off: u64 = c & 0x7f;
                while (c & 0x80 != 0) {
                    if (pos >= body.len or off > (1 << 56)) return bad(why, "a bad delta offset");
                    c = body[pos];
                    pos += 1;
                    off = ((off + 1) << 7) | (c & 0x7f);
                }
                if (off == 0 or off > at) return bad(why, "a delta's base is outside the pack");
                r.base_at = at - @as(usize, @intCast(off));
            },
            7 => {
                if (pos + 20 > body.len) return bad(why, "a bad delta base id");
                @memcpy(&r.base_id, body[pos .. pos + 20]);
                pos += 20;
            },
            else => return bad(why, "an object of unknown type"),
        }
        if (size > limits.bytes - total) return bad(why, "the pack unpacks to more than allowed");
        var in: std.Io.Reader = .fixed(body[pos..]);
        var z: flate.Decompress = .init(&in, .zlib, window);
        const data = z.reader.allocRemaining(a, .limited(@intCast(size + 1))) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => bad(why, "an object's data does not inflate"),
        };
        if (data.len != size) return bad(why, "an object's data is not its declared size");
        total += data.len;
        pos += in.seek;
        r.data = data;
        at_index.putAssumeCapacity(at, @intCast(i));
    }
    if (pos != body.len) return bad(why, "bytes after the last object");

    // Objects first, then deltas over resolved bases until none is left.
    const done = try a.alloc(?Object, count);
    @memset(done, null);
    var by_id: std.AutoHashMapUnmanaged([20]u8, u32) = .empty;
    try by_id.ensureTotalCapacity(a, count);
    var left: usize = count;
    for (raws, 0..) |r, i| if (r.type <= 4) {
        done[i] = try whole(a, @enumFromInt(r.type), r.data);
        by_id.putAssumeCapacity(done[i].?.id, @intCast(i));
        left -= 1;
    };
    while (left > 0) {
        var progress = false;
        for (raws, 0..) |r, i| {
            if (done[i] != null) continue;
            const b: u32 = if (r.type == 6)
                at_index.get(r.base_at) orelse return bad(why, "a delta's base is not an object of the pack")
            else
                by_id.get(r.base_id) orelse continue;
            const base = done[b] orelse continue;
            const content = try apply(a, base.content, r.data, limits.bytes - total, why);
            total += content.len;
            done[i] = try whole(a, base.kind, content);
            if (!by_id.contains(done[i].?.id)) by_id.putAssumeCapacity(done[i].?.id, @intCast(i));
            left -= 1;
            progress = true;
        }
        if (!progress) return bad(why, "a delta whose base is not in the pack (a thin pack?)");
    }
    const objects = try a.alloc(Object, count);
    for (done, objects) |d, *o| o.* = d.?;
    return .{ .objects = objects, .by_id = by_id };
}

/// An object as git hashes it, and its id.
pub fn whole(a: Allocator, kind: Kind, content: []const u8) !Object {
    const object = try std.fmt.allocPrint(a, "{s} {d}\x00{s}", .{ kind.name(), content.len, content });
    var id: [20]u8 = undefined;
    Sha1.hash(object, &id, .{});
    return .{ .kind = kind, .id = id, .object = object, .content = object[object.len - content.len ..] };
}

fn varint(d: []const u8, pos: *usize) ?u64 {
    var v: u64 = 0;
    var shift: u6 = 0;
    while (pos.* < d.len) {
        const c = d[pos.*];
        pos.* += 1;
        v |= @as(u64, c & 0x7f) << shift;
        if (c & 0x80 == 0) return v;
        if (shift > 56) return null;
        shift += 7;
    }
    return null;
}

/// Apply a git delta to `base`: its source and target sizes, then copy
/// (from the base) and insert (literal) instructions.
pub fn apply(a: Allocator, base: []const u8, delta: []const u8, max: usize, why: *[]const u8) Error![]u8 {
    var pos: usize = 0;
    const src = varint(delta, &pos) orelse return bad(why, "a bad delta");
    const dst = varint(delta, &pos) orelse return bad(why, "a bad delta");
    if (src != base.len) return bad(why, "a delta for another base (its source size differs)");
    if (dst > max) return bad(why, "the pack unpacks to more than allowed");
    const out = try a.alloc(u8, @intCast(dst));
    var o: usize = 0;
    while (pos < delta.len) {
        const op = delta[pos];
        pos += 1;
        if (op & 0x80 != 0) {
            var off: usize = 0;
            var n: usize = 0;
            inline for (0..4) |k| if (op & (1 << k) != 0) {
                if (pos >= delta.len) return bad(why, "a bad delta");
                off |= @as(usize, delta[pos]) << (8 * k);
                pos += 1;
            };
            inline for (0..3) |k| if (op & (0x10 << k) != 0) {
                if (pos >= delta.len) return bad(why, "a bad delta");
                n |= @as(usize, delta[pos]) << (8 * k);
                pos += 1;
            };
            if (n == 0) n = 0x10000;
            if (off > base.len or n > base.len - off or n > out.len - o) return bad(why, "a delta copies outside its base or target");
            @memcpy(out[o .. o + n], base[off .. off + n]);
            o += n;
        } else if (op != 0) {
            const n: usize = op;
            if (n > delta.len - pos or n > out.len - o) return bad(why, "a delta inserts past its end");
            @memcpy(out[o .. o + n], delta[pos .. pos + n]);
            pos += n;
            o += n;
        } else return bad(why, "a delta with a reserved instruction (0)");
    }
    if (o != out.len) return bad(why, "a delta short of its target size");
    return out;
}

fn bad(why: *[]const u8, msg: []const u8) error{BadPack} {
    why.* = msg;
    return error.BadPack;
}

// ---------------------------------------------------------------- tests

const t = std.testing;

fn hexId(s: []const u8) [20]u8 {
    var id: [20]u8 = undefined;
    _ = std.fmt.hexToBytes(&id, s) catch unreachable;
    return id;
}

// testdata/deltas.pack: `git pack-objects` (a full pack of a three-commit
// repository whose one file grows, so its versions are deltas of each other:
// ofs-deltas), and testdata/refdelta.pack: the same objects with ref-deltas
// (`--no-delta-base-offset`). testdata/README.md says how they were made.
test "a pack with ofs-deltas and one with ref-deltas: every object, its id computed" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var why: []const u8 = "";
    inline for (.{ "testdata/deltas.pack", "testdata/refdelta.pack" }) |f| {
        const bytes = @embedFile(f);
        const p = try read(a, bytes, .{ .bytes = 1 << 20, .objects = 100 }, &why);
        try t.expectEqual(@as(usize, 9), p.objects.len);
        const head = p.get(hexId("ba40a44f457769933fb16753589b6317354d6d49")).?;
        try t.expectEqual(Kind.commit, head.kind);
        try t.expectStringStartsWith(head.content, "tree a930a7aa1c9194b284b33adaaf354e258b59e01f\n");
        const big = p.get(hexId("75ff566337d9ffe02ebff4535fc07c78fc594c27")).?;
        try t.expectEqual(Kind.blob, big.kind);
        for (p.objects) |o| {
            var id: [20]u8 = undefined;
            Sha1.hash(o.object, &id, .{});
            try t.expectEqualSlices(u8, &id, &o.id);
        }
    }
}

test "a corrupt pack is refused" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var why: []const u8 = "";
    const good = @embedFile("testdata/deltas.pack");
    const copy = try a.dupe(u8, good);
    copy[40] ^= 1;
    try t.expectError(error.BadPack, read(a, copy, .{ .bytes = 1 << 20, .objects = 100 }, &why));
    try t.expectStringStartsWith(why, "the pack's trailer");
    try t.expectError(error.BadPack, read(a, good, .{ .bytes = 100, .objects = 100 }, &why));
    try t.expectEqualStrings("the pack unpacks to more than allowed", why);
    try t.expectError(error.BadPack, read(a, good, .{ .bytes = 1 << 20, .objects = 3 }, &why));
    try t.expectError(error.BadPack, read(a, "PACK", .{ .bytes = 1, .objects = 1 }, &why));
}

test "a delta" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var why: []const u8 = "";
    // base "hello world", target "hello there world": copy 6, insert "there ", copy 5 from 6
    const delta = [_]u8{ 11, 17, 0x90, 6, 6 } ++ "there ".* ++ [_]u8{ 0x91, 6, 5 };
    try t.expectEqualStrings("hello there world", try apply(a, "hello world", &delta, 100, &why));
    try t.expectError(error.BadPack, apply(a, "hello", &delta, 100, &why));
    try t.expectError(error.BadPack, apply(a, "hello world", &delta, 5, &why));
}
