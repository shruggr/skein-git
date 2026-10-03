//! A commit's tree out of a pack: its entries, the files by path, and every
//! object it reaches — each looked up by the id its parent names, so what
//! is reached is exactly what the commit's hash commits to.
const std = @import("std");
const pack = @import("pack.zig");

const Allocator = std.mem.Allocator;
const eql = std.mem.eql;

pub const Entry = struct { mode: []const u8, name: []const u8, id: [20]u8 };

pub const Error = error{ Missing, BadTree, OutOfMemory };

/// A tree object's entries: "<mode> <name>\0<20-byte id>" each.
pub fn entries(a: Allocator, content: []const u8) Error![]const Entry {
    var out: std.ArrayList(Entry) = .empty;
    var b = content;
    while (b.len > 0) {
        const sp = std.mem.indexOfScalar(u8, b, ' ') orelse return error.BadTree;
        const z = std.mem.indexOfScalar(u8, b, 0) orelse return error.BadTree;
        if (z < sp or z + 21 > b.len) return error.BadTree;
        var e: Entry = .{ .mode = b[0..sp], .name = b[sp + 1 .. z], .id = undefined };
        @memcpy(&e.id, b[z + 1 .. z + 21]);
        try out.append(a, e);
        b = b[z + 21 ..];
    }
    return out.items;
}

pub fn isTree(mode: []const u8) bool {
    return eql(u8, mode, "40000");
}

/// A submodule: a commit of another repository, not in this pack.
pub fn isGitlink(mode: []const u8) bool {
    return eql(u8, mode, "160000");
}

/// The commit's tree: the id on its first line, "tree <hex>".
pub fn treeOf(commit: []const u8) ?[20]u8 {
    if (commit.len < 46 or !std.mem.startsWith(u8, commit, "tree ") or commit[45] != '\n') return null;
    var id: [20]u8 = undefined;
    _ = std.fmt.hexToBytes(&id, commit[5..45]) catch return null;
    return id;
}

/// Every object the tree `root` reaches (itself first, then its entries,
/// depth first), each once. Gitlinks are entries, not objects: not followed.
/// An entry the pack does not hold is `Missing`, its path in `why`.
pub fn reachable(a: Allocator, p: *const pack.Pack, root: [20]u8, why: *[]const u8) Error![]const pack.Object {
    var out: std.ArrayList(pack.Object) = .empty;
    var seen: std.AutoHashMapUnmanaged([20]u8, void) = .empty;
    try visit(a, p, root, "", true, &out, &seen, why);
    return out.items;
}

fn visit(a: Allocator, p: *const pack.Pack, id: [20]u8, path: []const u8, tree: bool, out: *std.ArrayList(pack.Object), seen: *std.AutoHashMapUnmanaged([20]u8, void), why: *[]const u8) Error!void {
    if ((try seen.getOrPut(a, id)).found_existing) return;
    const o = p.get(id) orelse {
        why.* = try std.fmt.allocPrint(a, "the pack does not hold {s} ({x})", .{ if (path.len == 0) "the commit's tree" else path, &id });
        return error.Missing;
    };
    if (o.kind != (if (tree) pack.Kind.tree else pack.Kind.blob)) {
        why.* = try std.fmt.allocPrint(a, "{s} is a {s}, not a {s}", .{ if (path.len == 0) "the commit's tree" else path, o.kind.name(), if (tree) "tree" else "blob" });
        return error.BadTree;
    }
    try out.append(a, o);
    if (!tree) return;
    for (try entries(a, o.content)) |e| {
        if (isGitlink(e.mode)) continue;
        const sub = if (path.len == 0) e.name else try std.fmt.allocPrint(a, "{s}/{s}", .{ path, e.name });
        try visit(a, p, e.id, sub, isTree(e.mode), out, seen, why);
    }
}

/// The files of a tree in a pack, by path.
pub const Files = struct {
    pack: *const pack.Pack,
    root: [20]u8,

    /// The content of the regular file (or executable) at `path` ("etc/app.json"), or null.
    pub fn read(f: Files, a: Allocator, path: []const u8) Error!?[]const u8 {
        var at = f.root;
        var segs = std.mem.splitScalar(u8, path, '/');
        while (segs.next()) |seg| {
            const last = segs.peek() == null;
            const o = f.pack.get(at) orelse return null;
            if (o.kind != .tree) return null;
            const found = for (try entries(a, o.content)) |e| {
                if (eql(u8, e.name, seg)) break e;
            } else return null;
            if (!last and !isTree(found.mode)) return null;
            if (last and !eql(u8, found.mode, "100644") and !eql(u8, found.mode, "100755")) return null;
            at = found.id;
        }
        const o = f.pack.get(at) orelse return null;
        return if (o.kind == .blob) o.content else null;
    }
};

// ---------------------------------------------------------------- tests

const t = std.testing;

test "the tree of the test pack, its files, and what it reaches" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var why: []const u8 = "";
    const p = try pack.read(a, @embedFile("testdata/deltas.pack"), .{ .bytes = 1 << 20, .objects = 100 }, &why);
    var head: [20]u8 = undefined;
    _ = try std.fmt.hexToBytes(&head, "ba40a44f457769933fb16753589b6317354d6d49");
    const root = treeOf(p.get(head).?.content).?;
    const all = try reachable(a, &p, root, &why);
    try t.expectEqual(@as(usize, 2), all.len);
    try t.expectEqual(pack.Kind.tree, all[0].kind);
    try t.expectEqual(pack.Kind.blob, all[1].kind);
    const files: Files = .{ .pack = &p, .root = root };
    const f = (try files.read(a, "f.txt")).?;
    try t.expectStringStartsWith(f, "line 1 of the file");
    try t.expectStringEndsWith(f, "line 80 of the file that grows, so each version is a delta of another\n");
    try t.expect((try files.read(a, "nope")) == null);
    try t.expect((try files.read(a, "f.txt/x")) == null);
    // A tree the pack does not hold.
    var other = root;
    other[0] ^= 1;
    try t.expectError(error.Missing, reachable(a, &p, other, &why));
    try t.expectStringStartsWith(why, "the pack does not hold the commit's tree");
    try t.expect(treeOf("parent x\n") == null);
}
