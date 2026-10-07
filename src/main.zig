//! git (shruggr/skein#91): the git app. It clones one commit of a git
//! repository into the instance's store, by hash, and builds the app record
//! of its tree — so an app can be deployed from a page by two root-signed
//! messages: this one, then the install (`head`, `dispatch`, `start`).
//!
//!   a mailbox route  {address: "git", handler: "git.call"}, `call` gated by root (skein#143)
//!
//!   {fn: "git.clone", args: {url, hash}}      url: an http(s) git repository; hash: a commit id (40 hex)
//!     → {fn, request, replyTo, result: {tree: <cid>, app: <cid>}}
//!     → {fn, request, replyTo, error: {code, message}}
//!
//! The answer is a message to the sender in box `git` (when the address book
//! reaches it) and, either way, the thread's result (stdout, DAG-JSON).
//!
//! The request's thread (a message in the box is a thread of this program)
//! does three steps, each on one entry:
//!
//!   1. checks the call and emits GET <url>/info/refs?service=git-upload-pack
//!      (Git-Protocol: version=2) as a `fetch` intention (sk.fetch) — the
//!      runtime's HTTP proxy answers it — and rests on its answer;
//!   2. on the advertisement (a version 2 server offering shallow fetches):
//!      emits POST <url>/git-upload-pack, `fetch` of `want <hash>`, `deepen 1`
//!      (src/pkt.zig), and rests;
//!   3. on the response: takes the pack out of it (at most MAX_PACK bytes),
//!      unpacks it (src/pack.zig: ofs- and ref-deltas; every id computed),
//!      finds the commit whose id is `hash` and walks its tree (src/tree.zig):
//!      every object the commit names must be in the pack, so what arrived is
//!      what the hash commits to. It puts the commit and every tree and blob
//!      as git-raw blocks (sha1), builds the app record from the tree's
//!      etc/app.json (src/record.zig: the record and program records skein's
//!      install client builds for the same tree, byte for byte), puts those,
//!      keeps the commit, the tree and the app record, and answers.
//!
//! It holds no key, signs nothing but its own messages, and writes no head:
//! blocks are content-addressed and unscoped, so keeping them grants nothing
//! and mounts nothing. Only root's `head` message makes the tree an
//! app; root's `dispatch` messages give it routes.
//!
//! Error codes: bad-request (not {fn, args}), unknown-fn, bad-args (the url or
//! the hash is not one), unreachable (the HTTP proxy could not reach the
//! url), not-git (an HTTP status other than 200, or not a git protocol
//! version 2 server with shallow fetches), not-found (the server does not
//! hold the commit), too-large (the pack is over MAX_PACK, or unpacks to over
//! MAX_UNPACKED), mismatch (the pack is corrupt, or does not hold the commit
//! or what it names), no-manifest (the tree has no etc/app.json),
//! bad-manifest (the record cannot be built), failed.
const std = @import("std");
const cbor = @import("cbor");
const sk = @import("sk");
const app = @import("app");
const dagjson = @import("dagjson");
const pack = @import("pack.zig");
const pkt = @import("pkt.zig");
const tree = @import("tree.zig");
const record = @import("record.zig");

const cid = cbor.cidm;
const Value = cbor.Value;
const Allocator = std.mem.Allocator;
const eql = std.mem.eql;

pub const NAME = "git";
/// The one function: `<interface>.<function>` (skein-sdk `app`'s naming).
pub const CLONE = "git.clone";
/// The largest pack taken (its bytes as received, before unpacking).
pub const MAX_PACK: usize = 32 << 20;
/// What a pack may unpack to, and how many objects it may hold.
pub const MAX_UNPACKED: usize = 256 << 20;
pub const MAX_OBJECTS: usize = 200_000;
/// The largest advertisement taken.
const MAX_ADVERTISEMENT: usize = 1 << 20;
/// How long the HTTP proxy waits for each request.
const TIMEOUT_MS: i64 = 120_000;

pub fn main() u8 {
    return sk.main(NAME, run);
}

pub const Failure = struct { code: []const u8, message: []const u8 };
const Outcome = union(enum) { wait, ok: Value, fail: Failure };

fn fail(code: []const u8, message: []const u8) Outcome {
    return .{ .fail = .{ .code = code, .message = message } };
}

fn run(a: Allocator) !void {
    const in = try sk.input(a);
    const kind = Value.str(in.get("kind")) orelse "";
    if (eql(u8, kind, "call")) return sk.report("git.clone fetches through the fetch intention: send it as a message to box git (an in-VM call cannot emit)");
    if (!eql(u8, kind, "step")) return sk.report("git is stepped on a message in its box");
    const args = in.get("args") orelse return sk.report("no args");
    const message = Value.cidOf(args.get("message")) orelse return sk.report("not a message (no message)");
    const body = try sk.get(a, Value.cidOf(args.get("body")) orelse return sk.report("not a message (no body)"));
    if (body != .map or body.get("fn") == null) return sk.report("not a call: want {fn: \"git.clone\", args: {url, hash}}");
    const name = Value.str(body.get("fn")) orelse "";
    const outcome = clone(a, in, body) catch |e| fail("failed", try a.dupe(u8, sk.errorText(e)));
    if (outcome == .wait) return;
    var ans = cbor.MapBuilder.init(a);
    try ans.put("fn", cbor.string(name));
    try ans.put("request", cbor.cidv(message));
    try ans.put("replyTo", cbor.cidv(message));
    switch (outcome) {
        .ok => |v| try ans.put("result", v),
        .fail => |f| {
            var e = cbor.MapBuilder.init(a);
            try e.put("code", cbor.string(f.code));
            try e.put("message", cbor.string(f.message));
            try ans.put("error", e.value());
        },
        .wait => unreachable,
    }
    // Answered to the sender when the address book reaches it (skein-sdk app's way).
    if (Value.bytesOf(args.get("sender"))) |s| if (try sk.peerOf(a, s) != null) {
        _ = try sk.emit(a, s, Value.str(args.get("box")) orelse NAME, ans.value(), null);
    };
    try std.Io.File.stdout().writeStreamingAll(sk.io(), try dagjson.encode(a, ans.value()));
}

/// Where the thread is: the last stage record it kept, {kind: "git-clone",
/// stage: "refs" | "pack", url, hash, fetch: <the request awaited>}.
fn stageOf(a: Allocator, in: Value) !?Value {
    const tip = Value.cidOf(in.get("tip")) orelse return null;
    var last: ?Value = null;
    for (try sk.kept(a, tip)) |k| {
        const v = sk.get(a, k) catch continue;
        if (eql(u8, Value.str(v.get("kind")) orelse "", "git-clone")) last = v;
    }
    return last;
}

fn clone(a: Allocator, in: Value, body: Value) !Outcome {
    const st = try stageOf(a, in);
    const reply = try sk.replyOf(a, in);
    if (reply == null) {
        if (st != null) return sk.report("stepped again without the HTTP proxy's answer");
        return start(a, body);
    }
    const s = st orelse return sk.report("an answer with no clone under way");
    const r = reply.?;
    if (!eql(u8, r.reply_to, Value.cidOf(s.get("fetch")) orelse "")) return sk.report("an answer to another message");
    const url = Value.str(s.get("url")).?;
    const hash = Value.str(s.get("hash")).?;
    if (Value.str(r.body.get("error"))) |e| return fail("unreachable", try std.fmt.allocPrint(a, "{s}: {s}", .{ url, e }));
    const status = Value.intOf(r.body.get("status")) orelse 0;
    const got = Value.bytesOf(r.body.get("body")) orelse "";
    const stage = Value.str(s.get("stage")) orelse "";
    var why: []const u8 = "";
    if (eql(u8, stage, "refs")) {
        if (status != 200) return fail("not-git", try std.fmt.allocPrint(a, "{s}/info/refs: HTTP {d} (not a git repository served over smart HTTP)", .{ url, status }));
        const caps = pkt.advertisement(got, &why) catch |e| return switch (e) {
            error.OutOfMemory => e,
            else => fail("not-git", try std.fmt.allocPrint(a, "{s}: {s}", .{ url, if (e == error.Refused) why else "the advertisement is not pkt-lines" })),
        };
        const req = try pkt.fetchRequest(a, hash, caps);
        const id = try fetch(a, "POST", try std.fmt.allocPrint(a, "{s}/git-upload-pack", .{url}), &.{
            .{ "content-type", "application/x-git-upload-pack-request" },
            .{ "accept", "application/x-git-upload-pack-result" },
        }, req, MAX_PACK + (1 << 20));
        try keepStage(a, "pack", url, hash, id);
        return .wait;
    }
    if (!eql(u8, stage, "pack")) return sk.report("an unknown stage");
    if (status != 200) return fail("not-git", try std.fmt.allocPrint(a, "{s}/git-upload-pack: HTTP {d}", .{ url, status }));
    const bytes = pkt.packOf(a, got, MAX_PACK, &why) catch |e| return switch (e) {
        error.OutOfMemory => e,
        error.Refused => if (std.mem.indexOf(u8, why, "not our ref") != null)
            fail("not-found", try std.fmt.allocPrint(a, "{s} does not hold commit {s} ({s})", .{ url, hash, why }))
        else if (std.mem.startsWith(u8, why, "the pack is larger"))
            fail("too-large", why)
        else
            fail("not-git", why),
        else => fail("not-git", "the fetch response is not pkt-lines"),
    };
    return finish(a, in, url, hash, bytes);
}

/// Step 1: check the call, ask for the advertisement.
fn start(a: Allocator, body: Value) !Outcome {
    const name = Value.str(body.get("fn")) orelse return fail("bad-request", "fn is not text");
    const manifest = try app.manifestOf(a, NAME);
    const decl = (try app.declOf(a, manifest, name)) orelse return fail("unknown-fn", try std.fmt.allocPrint(a, "{s}: not provided by git", .{name}));
    if (!eql(u8, name, CLONE)) return fail("unknown-fn", try std.fmt.allocPrint(a, "{s}: declared, not implemented", .{name}));
    const args: Value = switch (body.get("args") orelse Value.null) {
        .null => .{ .map = &.{} },
        else => |v| v,
    };
    if (try app.check(a, decl.get("args") orelse Value{ .map = &.{} }, args, "args")) |w| return fail("bad-args", w);
    const url = repoUrl(Value.str(args.get("url")).?) orelse return fail("bad-args", "args.url: not an http(s) URL of a git repository");
    const hash = commitId(a, Value.str(args.get("hash")).?) orelse return fail("bad-args", "args.hash: not a commit id (40 hex digits)");
    const id = try fetch(a, "GET", try std.fmt.allocPrint(a, "{s}/info/refs?service=git-upload-pack", .{url}), &.{}, null, MAX_ADVERTISEMENT);
    try keepStage(a, "refs", url, hash, id);
    return .wait;
}

/// Step 3: the pack, checked against the hash; the blocks and the app record.
fn finish(a: Allocator, in: Value, url: []const u8, hash: []const u8, bytes: []const u8) !Outcome {
    _ = url;
    var why: []const u8 = "";
    const p = pack.read(a, bytes, .{ .bytes = MAX_UNPACKED, .objects = MAX_OBJECTS }, &why) catch |e| return switch (e) {
        error.OutOfMemory => e,
        error.BadPack => fail(if (std.mem.indexOf(u8, why, "more than allowed") != null) "too-large" else "mismatch", why),
    };
    var id: [20]u8 = undefined;
    _ = std.fmt.hexToBytes(&id, hash) catch unreachable;
    const commit = p.get(id) orelse return fail("mismatch", try std.fmt.allocPrint(a, "the pack does not hold commit {s}", .{hash}));
    if (commit.kind != .commit) return fail("mismatch", try std.fmt.allocPrint(a, "{s} is a {s}, not a commit", .{ hash, commit.kind.name() }));
    const root = tree.treeOf(commit.content) orelse return fail("mismatch", "the commit names no tree");
    const objects = tree.reachable(a, &p, root, &why) catch |e| return switch (e) {
        error.OutOfMemory => e,
        else => fail("mismatch", why),
    };
    // The commit and what it names, as git-raw blocks (CIDv1 git-raw sha1: the id).
    const commit_cid = try cid.create(a, cid.GIT_RAW, cid.SHA1, &commit.id);
    try sk.putBlock(commit_cid, commit.object);
    for (objects) |o| try sk.putBlock(try cid.create(a, cid.GIT_RAW, cid.SHA1, &o.id), o.object);
    const tree_cid = try cid.create(a, cid.GIT_RAW, cid.SHA1, &root);

    const files: tree.Files = .{ .pack = &p, .root = root };
    const built = record.build(a, files, tree_cid, .{ .programs = in.get("programs") orelse .null, .state = try installedState(a, files), .has = holds }, &why) catch |e| return switch (e) {
        error.OutOfMemory => e,
        error.NoManifest => fail("no-manifest", why),
        error.BadManifest => fail("bad-manifest", why),
    };
    for (built.blocks) |b| try sk.putBlock(b.cid, b.bytes);
    try sk.keep(commit_cid);
    try sk.keep(tree_cid);
    try sk.keep(built.app);
    var m = cbor.MapBuilder.init(a);
    try m.put("tree", cbor.cidv(tree_cid));
    try m.put("app", cbor.cidv(built.app));
    return .{ .ok = m.value() };
}

/// The `state` of the app the tree names, if it is installed (the root of `<name>/app`): carried over, as the install does.
fn installedState(a: Allocator, files: tree.Files) !?[]const u8 {
    const text = (try files.read(a, "etc/app.json")) orelse return null;
    const m = dagjson.decode(a, text) catch return null;
    const name = Value.str(m.get("name")) orelse return null;
    const root = (try sk.head(a, try app.headOf(a, name))) orelse return null;
    const r = sk.get(a, root) catch return null;
    if (!eql(u8, Value.str(r.get("kind")) orelse "", "app")) return null;
    return Value.cidOf(r.get("state"));
}

/// Whether the store holds a block.
fn holds(a: Allocator, c: []const u8) anyerror!bool {
    _ = sk.getBytes(a, c) catch |e| {
        if (e == error.ImportFailed and std.mem.startsWith(u8, sk.lastError(), "not found")) return false;
        return e;
    };
    return true;
}

/// One HTTP request as an intention (shruggr/skein#126: sk.fetch's `fetch`
/// event, which the runtime sends, signed, to its HTTP proxy) → its CID, awaited.
fn fetch(a: Allocator, method: []const u8, url: []const u8, headers: []const [2][]const u8, body: ?[]const u8, max: usize) ![]const u8 {
    var h = cbor.MapBuilder.init(a);
    try h.put("git-protocol", cbor.string("version=2"));
    for (headers) |x| try h.put(x[0], cbor.string(x[1]));
    return sk.fetchWith(a, method, url, h.value(), body, .{ .timeout_ms = TIMEOUT_MS, .max_bytes = @intCast(max) });
}

fn keepStage(a: Allocator, stage: []const u8, url: []const u8, hash: []const u8, request: []const u8) !void {
    var m = cbor.MapBuilder.init(a);
    try m.put("kind", cbor.string("git-clone"));
    try m.put("stage", cbor.string(stage));
    try m.put("url", cbor.string(url));
    try m.put("hash", cbor.string(hash));
    try m.put("fetch", cbor.cidv(request));
    try sk.keep(try sk.put(a, m.value()));
}

/// An http(s) URL of a repository, without a trailing slash; null if not one.
pub fn repoUrl(s: []const u8) ?[]const u8 {
    if (s.len > 2048) return null;
    const rest = if (std.mem.startsWith(u8, s, "https://")) s[8..] else if (std.mem.startsWith(u8, s, "http://")) s[7..] else return null;
    if (rest.len == 0 or rest[0] == '/') return null;
    for (s) |c| if (c <= ' ' or c == 0x7f or c == '?' or c == '#' or c == '\\') return null;
    return std.mem.trimEnd(u8, s, "/");
}

/// A commit id: 40 hex digits, lower-cased.
pub fn commitId(a: Allocator, s: []const u8) ?[]const u8 {
    if (s.len != 40) return null;
    for (s) |c| if (!std.ascii.isHex(c)) return null;
    return std.ascii.allocLowerString(a, s) catch null;
}

// ---------------------------------------------------------------- tests

test {
    _ = pkt;
    _ = pack;
    _ = tree;
    _ = record;
}

test "the url and the hash" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectEqualStrings("https://github.com/shruggr/skein-git", repoUrl("https://github.com/shruggr/skein-git/").?);
    try std.testing.expectEqualStrings("http://127.0.0.1:9/repo.git", repoUrl("http://127.0.0.1:9/repo.git").?);
    try std.testing.expect(repoUrl("ftp://x/y") == null);
    try std.testing.expect(repoUrl("https://x/y?z") == null);
    try std.testing.expect(repoUrl("https:///y") == null);
    try std.testing.expect(repoUrl("https://x/a b") == null);
    try std.testing.expectEqualStrings("ba40a44f457769933fb16753589b6317354d6d49", commitId(a, "BA40A44F457769933FB16753589B6317354D6D49").?);
    try std.testing.expect(commitId(a, "ba40a44") == null);
    try std.testing.expect(commitId(a, "za40a44f457769933fb16753589b6317354d6d49") == null);
}
