//! Git's smart HTTP, protocol version 2, as a client that asks for one
//! commit (gitprotocol-http(5), gitprotocol-v2(5), gitprotocol-common(5)):
//!
//!   GET  <url>/info/refs?service=git-upload-pack     Git-Protocol: version=2
//!        → the capability advertisement: [# service=git-upload-pack, flush,]
//!          "version 2", then one capability per line ("fetch=shallow …",
//!          "object-format=sha1", …), flush
//!   POST <url>/git-upload-pack                       Git-Protocol: version=2
//!        command=fetch [object-format=sha1] delim
//!        no-progress ofs-delta want <hash> deepen 1 done flush
//!        → sections, each a header line then lines: "shallow-info" (the
//!          commit made shallow), "packfile" (side-band: band 1 the pack,
//!          2 progress, 3 a fatal error), ended by a flush; or "ERR <message>"
//!
//! A version 2 server serves any commit reachable from its refs by id (git's
//! upload-pack does by default; so do the forges), so the advertisement
//! carries no refs and none are listed: the want is the hash itself. A
//! server that speaks only version 0/1 answers the advertisement with refs
//! instead of "version 2" and is refused (it would serve only advertised
//! tips by id). No `thin-pack`: the pack is self-contained.
//!
//! Every line is a pkt-line: four hex digits of length (itself included),
//! then the data; 0000 flush, 0001 delim, 0002 response-end.
const std = @import("std");

const Allocator = std.mem.Allocator;
const eql = std.mem.eql;

pub const Pkt = union(enum) { flush, delim, end, data: []const u8 };

pub const Error = error{ BadPktLine, Refused, OutOfMemory };

/// The next pkt-line of `buf` from `pos.*`, or null at the end of the buffer.
pub fn next(buf: []const u8, pos: *usize) Error!?Pkt {
    if (pos.* >= buf.len) return null;
    if (buf.len - pos.* < 4) return error.BadPktLine;
    const n = std.fmt.parseInt(u16, buf[pos.* .. pos.* + 4], 16) catch return error.BadPktLine;
    switch (n) {
        0 => {
            pos.* += 4;
            return .flush;
        },
        1 => {
            pos.* += 4;
            return .delim;
        },
        2 => {
            pos.* += 4;
            return .end;
        },
        3 => return error.BadPktLine,
        else => {},
    }
    if (pos.* + n > buf.len) return error.BadPktLine;
    const d = buf[pos.* + 4 .. pos.* + n];
    pos.* += n;
    return .{ .data = d };
}

/// A line's text without its trailing newline.
fn line(d: []const u8) []const u8 {
    return if (d.len > 0 and d[d.len - 1] == '\n') d[0 .. d.len - 1] else d;
}

/// Append one pkt-line carrying `data`.
pub fn put(a: Allocator, out: *std.ArrayList(u8), data: []const u8) !void {
    var h: [4]u8 = undefined;
    _ = std.fmt.bufPrint(&h, "{x:0>4}", .{data.len + 4}) catch unreachable;
    try out.appendSlice(a, &h);
    try out.appendSlice(a, data);
}

/// What the advertisement says about fetching.
pub const Caps = struct {
    /// `fetch=… shallow …`: the server takes `deepen`.
    shallow: bool = false,
    /// `object-format=…` was advertised (it is then sent back).
    object_format: bool = false,
};

/// Read a version 2 capability advertisement. A refusal sets `why`.
pub fn advertisement(body: []const u8, why: *[]const u8) Error!Caps {
    var pos: usize = 0;
    var first = (try next(body, &pos)) orelse return refuse(why, "the advertisement is empty");
    // Smart HTTP may open with "# service=git-upload-pack" and a flush.
    if (first == .data and std.mem.startsWith(u8, first.data, "# service=")) {
        const f = (try next(body, &pos)) orelse return refuse(why, "the advertisement ends after its service line");
        if (f != .flush) return refuse(why, "the advertisement's service line is not followed by a flush");
        first = (try next(body, &pos)) orelse return refuse(why, "the advertisement has no capabilities");
    }
    if (first != .data or !eql(u8, line(first.data), "version 2"))
        return refuse(why, "the server does not speak git protocol version 2 (it answered with refs: version 0/1)");
    var caps: Caps = .{};
    var fetch = false;
    while (try next(body, &pos)) |p| switch (p) {
        .flush => break,
        .data => |d| {
            const l = line(d);
            const eq = std.mem.indexOfScalar(u8, l, '=') orelse l.len;
            const key = l[0..eq];
            const value = if (eq < l.len) l[eq + 1 ..] else "";
            if (eql(u8, key, "fetch")) {
                fetch = true;
                var it = std.mem.tokenizeScalar(u8, value, ' ');
                while (it.next()) |f| if (eql(u8, f, "shallow")) {
                    caps.shallow = true;
                };
            } else if (eql(u8, key, "object-format")) {
                if (!eql(u8, value, "sha1")) return refuse(why, "the repository's object format is not sha1");
                caps.object_format = true;
            }
        },
        else => return refuse(why, "the advertisement is malformed"),
    };
    if (!fetch) return refuse(why, "the server does not offer fetch");
    if (!caps.shallow) return refuse(why, "the server does not offer shallow fetches (fetch=shallow)");
    return caps;
}

/// The fetch command for one commit, shallow (depth 1): the request body.
pub fn fetchRequest(a: Allocator, hash: []const u8, caps: Caps) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try put(a, &out, "command=fetch\n");
    if (caps.object_format) try put(a, &out, "object-format=sha1\n");
    try out.appendSlice(a, "0001");
    try put(a, &out, "no-progress\n");
    try put(a, &out, "ofs-delta\n");
    try put(a, &out, try std.fmt.allocPrint(a, "want {s}\n", .{hash}));
    try put(a, &out, "deepen 1\n");
    try put(a, &out, "done\n");
    try out.appendSlice(a, "0000");
    return out.items;
}

/// The pack in a fetch response: the packfile section's band-1 data, at most
/// `max` bytes. An `ERR` line, a band-3 message, no packfile section or a
/// pack over `max` is a refusal (`why`).
pub fn packOf(a: Allocator, body: []const u8, max: usize, why: *[]const u8) Error![]const u8 {
    var pos: usize = 0;
    var pack: std.ArrayList(u8) = .empty;
    while (try next(body, &pos)) |head| {
        const h = switch (head) {
            .data => |d| line(d),
            .flush, .end => break,
            .delim => continue,
        };
        if (std.mem.startsWith(u8, h, "ERR ")) return refuse(why, try a.dupe(u8, h[4..]));
        const is_pack = eql(u8, h, "packfile");
        if (!is_pack and !eql(u8, h, "acknowledgments") and !eql(u8, h, "shallow-info") and !eql(u8, h, "wanted-refs") and !eql(u8, h, "packfile-uris"))
            return refuse(why, try std.fmt.allocPrint(a, "an unknown section in the fetch response: {s}", .{h[0..@min(h.len, 60)]}));
        while (try next(body, &pos)) |p| switch (p) {
            .data => |d| {
                if (std.mem.startsWith(u8, d, "ERR ")) return refuse(why, try a.dupe(u8, line(d[4..])));
                if (!is_pack) continue;
                if (d.len == 0) return refuse(why, "an empty side-band line");
                switch (d[0]) {
                    1 => {
                        if (pack.items.len + d.len - 1 > max) return refuse(why, try std.fmt.allocPrint(a, "the pack is larger than {d} bytes", .{max}));
                        try pack.appendSlice(a, d[1..]);
                    },
                    2 => {},
                    3 => return refuse(why, try std.fmt.allocPrint(a, "the server: {s}", .{line(d[1..])})),
                    else => return refuse(why, "a side-band line on an unknown band"),
                }
            },
            .delim => break,
            .flush, .end => if (is_pack) return pack.items else break,
        };
        if (is_pack) return pack.items;
    }
    return refuse(why, "the fetch response has no packfile section");
}

fn refuse(why: *[]const u8, msg: []const u8) error{Refused} {
    why.* = msg;
    return error.Refused;
}

// ---------------------------------------------------------------- tests

const t = std.testing;

test "pkt-lines" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var out: std.ArrayList(u8) = .empty;
    try put(a, &out, "hello\n");
    try out.appendSlice(a, "00000001");
    var pos: usize = 0;
    try t.expectEqualStrings("000ahello\n00000001", out.items);
    try t.expectEqualStrings("hello\n", (try next(out.items, &pos)).?.data);
    try t.expect((try next(out.items, &pos)).? == .flush);
    try t.expect((try next(out.items, &pos)).? == .delim);
    try t.expect((try next(out.items, &pos)) == null);
    pos = 0;
    try t.expectError(error.BadPktLine, next("00zz", &pos));
    pos = 0;
    try t.expectError(error.BadPktLine, next("0010short", &pos));
}

test "the advertisement" {
    var why: []const u8 = "";
    // git http-backend, protocol v2 (no service line)
    const plain = "000eversion 2\n001bagent=git/2.55.0-Linux\n0013ls-refs=unborn\n0020fetch=shallow wait-for-done\n0012server-option\n0017object-format=sha1\n0000";
    const c = try advertisement(plain, &why);
    try t.expect(c.shallow and c.object_format);
    // With the service line first
    const svc = "001e# service=git-upload-pack\n0000000eversion 2\n0012fetch=shallow\n0000";
    const d = try advertisement(svc, &why);
    try t.expect(d.shallow and !d.object_format);
    // A v0 server: refs
    try t.expectError(error.Refused, advertisement("003c42643a3330e2f87a71b35b83502b32cd28762a56 HEAD\x00multi_ack\n0000", &why));
    try t.expectStringStartsWith(why, "the server does not speak git protocol version 2");
    // No shallow
    try t.expectError(error.Refused, advertisement("000eversion 2\n000bfetch=\n0000", &why));
    try t.expectStringStartsWith(why, "the server does not offer shallow");
    try t.expectError(error.Refused, advertisement("000eversion 2\n0012fetch=shallow\n0019object-format=sha256\n0000", &why));
}

test "the fetch request" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const r = try fetchRequest(arena.allocator(), "42643a3330e2f87a71b35b83502b32cd28762a56", .{ .shallow = true, .object_format = true });
    try t.expectEqualStrings("0012command=fetch\n0017object-format=sha1\n00010010no-progress\n000eofs-delta\n0032want 42643a3330e2f87a71b35b83502b32cd28762a56\n000ddeepen 1\n0009done\n0000", r);
}

test "the pack in a response" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var why: []const u8 = "";
    const ok = "0011shallow-info\n0035shallow 42643a3330e2f87a71b35b83502b32cd28762a56\n0001000dpackfile\n0009\x01PACK0007\x02..0007\x01xy0000";
    try t.expectEqualStrings("PACKxy", try packOf(a, ok, 100, &why));
    try t.expectError(error.Refused, packOf(a, ok, 5, &why));
    try t.expectEqualStrings("the pack is larger than 5 bytes", why);
    try t.expectError(error.Refused, packOf(a, "0032ERR upload-pack: not our ref 1111111111111111\n", 100, &why));
    try t.expectEqualStrings("upload-pack: not our ref 1111111111111111", why);
    try t.expectError(error.Refused, packOf(a, "000dpackfile\n0009\x03boom0000", 100, &why));
    try t.expectEqualStrings("the server: boom", why);
    try t.expectError(error.Refused, packOf(a, "0011shallow-info\n0000", 100, &why));
    try t.expectEqualStrings("the fetch response has no packfile section", why);
}
