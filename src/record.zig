//! The app record of a tree (skein docs/APPS.md §2, §3): what the owner's
//! `head` message names as the root of `<app>/app`. The same record, byte for
//! byte, as skein's install client builds for the same tree
//! (src/host/install.ts `planInstall`, src/host/manifest.ts `checkManifest`):
//!
//!   {kind: "app", name, version, …every other field of etc/app.json as written,
//!    programs: {<role>: <program record CID>},
//!    dispatch: [<the manifest's rows, `transport` defaulted to "mailbox">,
//!               <the rows config.overlay derives, unless a row has the key>],
//!    provides: [] if absent, requires: [] if absent,
//!    tree: <the tree's CID>, state?: <the installed app's state, carried over>}
//!
//! and the blocks it stands on: each module a raw block (CIDv1 raw sha2-256 of
//! the file `bin/<x>.wasm`), each program record (dag-cbor):
//!
//!   bin/<x>.wasm | bin/<x>.cid   {kind: "program", name: <x>, code: {wasm: <module>}, inputs, services,
//!                                 description, app}  — inputs/services/description from bin/<x>.json
//!                                 if the tree has it (else the handler's inputs, [], "<x> (from the
//!                                 system tree)"); a .cid names a module the instance already holds
//!   <a genesis program's name>   that program's record, as the step's input `programs` names it
//!   {code: "shell", modules, support?, description?}
//!                                {kind: "program", name: <role>, code: {ts: "shell"}, modules: {<command>:
//!                                 <raw CID>}, support: {<command>: {mount, files: {<path>: <raw CID>}, env}},
//!                                 inputs, services: [], description, app}
//!
//! What is checked here is what the record needs. The rest of the manifest's
//! rules (row shapes, reserved names, interfaces) are the install client's:
//! it reads the manifest out of the stored tree, checks it, rebuilds this
//! record and compares the CID before the owner signs the head.
const std = @import("std");
const cbor = @import("cbor");
const dagjson = @import("dagjson");

const cid = cbor.cidm;
const Value = cbor.Value;
const Allocator = std.mem.Allocator;
const eql = std.mem.eql;

pub const Error = error{ NoManifest, BadManifest, OutOfMemory };

pub const Block = struct { cid: []const u8, bytes: []const u8 };

pub const Built = struct {
    name: []const u8,
    /// The app record's CID, and the record.
    app: []const u8,
    record: Value,
    /// Raw modules and files, program records, the app record last: each once.
    blocks: []const Block,
};

/// What the record needs of the instance.
pub const Instance = struct {
    /// The genesis programs (name → program record CID): the step input's `programs`.
    programs: Value = .null,
    /// The installed app's `state` (the root of `<name>/app`), carried over.
    state: ?[]const u8 = null,
    /// Whether the instance holds a block (a `bin/<x>.cid` module).
    has: *const fn (Allocator, []const u8) anyerror!bool,
};

/// The program inputs of a handler (src/host/boot.ts HANDLER_INPUTS).
const HANDLER_INPUTS = .{ .{ "message", "cid" }, .{ "body", "cid" }, .{ "box", "string" }, .{ "sender", "identity" } };
/// The program inputs of a shell program (src/host/install.ts SHELL_INPUTS).
const SHELL_INPUTS = .{ .{ "cmd", "string" }, .{ "tree", "cid" }, .{ "cwd", "string?" }, .{ "env", "map?" } };
const SHELL_DESCRIPTION = "Run a bash command in the wasm shell over a tree; result {exitCode, stdout, stderr, tree}.";
/// The overlay engine's role (src/host/manifest.ts OVERLAY_ROLE).
const OVERLAY_ROLE = "overlay";

fn textMap(a: Allocator, comptime pairs: anytype) !Value {
    var m = cbor.MapBuilder.init(a);
    inline for (pairs) |p| try m.put(p[0], cbor.string(p[1]));
    return m.value();
}

const Build = struct {
    a: Allocator,
    files: *const anyopaque,
    read: *const fn (*const anyopaque, Allocator, []const u8) anyerror!?[]const u8,
    inst: Instance,
    app: []const u8,
    why: *[]const u8,
    blocks: std.ArrayList(Block) = .empty,
    seen: std.StringHashMapUnmanaged(void) = .empty,

    fn bad(b: *Build, comptime fmt: []const u8, args: anytype) Error {
        b.why.* = std.fmt.allocPrint(b.a, "etc/app.json: " ++ fmt, args) catch "etc/app.json: not an app manifest";
        return error.BadManifest;
    }

    fn file(b: *Build, path: []const u8) Error!?[]const u8 {
        return b.read(b.files, b.a, path) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => b.bad("reading {s}: {s}", .{ path, @errorName(e) }),
        };
    }

    fn add(b: *Build, c: []const u8, bytes: []const u8) !void {
        if ((try b.seen.getOrPut(b.a, c)).found_existing) return;
        try b.blocks.append(b.a, .{ .cid = c, .bytes = bytes });
    }

    /// A raw block of a file of the tree: its CID. `want`: any file, a wasm
    /// module or component (a program), a module only (a shell's command).
    fn raw(b: *Build, path: []const u8, want: enum { file, wasm, module }, at: []const u8) Error![]const u8 {
        const bytes = (try b.file(path)) orelse return b.bad("{s}: {s} is not in the tree", .{ at, path });
        switch (want) {
            .file => {},
            .wasm => _ = wasmKind(bytes) orelse return b.bad("{s}: {s} is not a wasm module or component", .{ at, path }),
            .module => if (wasmKind(bytes) != .module) return b.bad("{s}: {s} is not a wasm module (a shell program runs WASI preview1 modules)", .{ at, path }),
        }
        const c = try cid.ofRaw(b.a, bytes);
        try b.add(c, bytes);
        return c;
    }

    fn record(b: *Build, v: Value) Error![]const u8 {
        const blk = cbor.block(b.a, v) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => b.bad("a value that is not IPLD (NaN or Infinity)", .{}),
        };
        try b.add(blk.cid, blk.bytes);
        return blk.cid;
    }

    /// One role's program record → its CID.
    fn program(b: *Build, role: []const u8, src: Value) Error![]const u8 {
        const at = try std.fmt.allocPrint(b.a, "programs.{s}", .{role});
        if (src == .map) return b.shell(role, src, at);
        const s = Value.str(src) orelse return b.bad("{s}: not bin/<x>.wasm, bin/<x>.cid, a program name or a shell program", .{at});
        if (binFile(s)) |f| {
            const module: []const u8 = if (eql(u8, f.ext, "wasm"))
                try b.raw(s, .wasm, at)
            else blk: {
                const text = (try b.file(s)) orelse return b.bad("{s}: {s} is not in the tree", .{ at, s });
                const m = cid.parse(b.a, std.mem.trim(u8, text, " \t\r\n")) catch return b.bad("{s}: {s} is not a CID", .{ at, s });
                if (cid.codecOf(m) != cid.RAW) return b.bad("{s}: {s} names a CID that is not a raw module", .{ at, s });
                const held = b.inst.has(b.a, m) catch false;
                if (!held) return b.bad("{s}: {s} names {s}, which the instance does not hold", .{ at, s, try cid.format(b.a, m) });
                break :blk m;
            };
            // bin/<x>.json beside it: the record's inputs, services, description.
            var meta: Value = .{ .map = &.{} };
            if (try b.file(try std.fmt.allocPrint(b.a, "bin/{s}.json", .{f.name}))) |j| {
                meta = dagjson.decode(b.a, j) catch return b.bad("bin/{s}.json: not JSON", .{f.name});
                if (meta != .map) return b.bad("bin/{s}.json: not a JSON object", .{f.name});
            }
            var r = cbor.MapBuilder.init(b.a);
            try r.put("kind", cbor.string("program"));
            try r.put("name", cbor.string(f.name));
            var code = cbor.MapBuilder.init(b.a);
            try code.put("wasm", cbor.cidv(module));
            try r.put("code", code.value());
            try r.put("inputs", given(meta, "inputs") orelse try textMap(b.a, HANDLER_INPUTS));
            try r.put("services", given(meta, "services") orelse Value{ .array = &.{} });
            try r.put("description", given(meta, "description") orelse cbor.string(try std.fmt.allocPrint(b.a, "{s} (from the system tree)", .{f.name})));
            try r.put("app", cbor.string(b.app));
            return b.record(r.value());
        }
        if (isProgramName(s)) {
            return Value.cidOf(b.inst.programs.get(s)) orelse b.bad("{s}: the instance has no program {s} in its genesis", .{ at, s });
        }
        return b.bad("{s}: {s} is not bin/<x>.wasm, bin/<x>.cid, a program name or a shell program", .{ at, s });
    }

    /// A shell program (#83; docs/APPS.md "A shell program").
    fn shell(b: *Build, role: []const u8, p: Value, at: []const u8) Error![]const u8 {
        if (!eql(u8, Value.str(p.get("code")) orelse "", "shell")) return b.bad("{s}: a program given as a map is a shell program: {{code: \"shell\", modules, support?}}", .{at});
        const mods = p.get("modules") orelse Value.null;
        if (mods != .map) return b.bad("{s}.modules: want {{<command>: \"bin/<x>.wasm\"}}", .{at});
        var modules = cbor.MapBuilder.init(b.a);
        for (mods.map) |e| {
            const path = Value.str(e.value) orelse return b.bad("{s}.modules.{s}: not bin/<x>.wasm", .{ at, e.key });
            try modules.put(e.key, cbor.cidv(try b.raw(path, .module, try std.fmt.allocPrint(b.a, "{s}.modules.{s}", .{ at, e.key }))));
        }
        var support = cbor.MapBuilder.init(b.a);
        if (p.get("support")) |sup| if (sup != .null) {
            if (sup != .map) return b.bad("{s}.support: want {{<command>: {{mount, files, env?}}}}", .{at});
            for (sup.map) |e| {
                const where = try std.fmt.allocPrint(b.a, "{s}.support.{s}", .{ at, e.key });
                const mount = Value.str(e.value.get("mount")) orelse return b.bad("{s}.mount: not an absolute path", .{where});
                const fs = e.value.get("files") orelse Value.null;
                if (fs != .map) return b.bad("{s}.files: want {{<path under the mount>: <a file in the tree>}}", .{where});
                var files = cbor.MapBuilder.init(b.a);
                for (fs.map) |f| {
                    const path = Value.str(f.value) orelse return b.bad("{s}.files.{s}: not a file in the tree", .{ where, f.key });
                    try files.put(f.key, cbor.cidv(try b.raw(path, .file, where)));
                }
                const env: Value = if (e.value.get("env")) |x| (if (x == .null) Value{ .map = &.{} } else x) else Value{ .map = &.{} };
                if (env != .map) return b.bad("{s}.env: want {{<name>: <text>}}", .{where});
                var s = cbor.MapBuilder.init(b.a);
                try s.put("mount", cbor.string(mount));
                try s.put("files", files.value());
                try s.put("env", env);
                try support.put(e.key, s.value());
            }
        };
        var r = cbor.MapBuilder.init(b.a);
        try r.put("kind", cbor.string("program"));
        try r.put("name", cbor.string(role));
        var code = cbor.MapBuilder.init(b.a);
        try code.put("ts", cbor.string("shell"));
        try r.put("code", code.value());
        try r.put("modules", modules.value());
        try r.put("support", support.value());
        try r.put("inputs", try textMap(b.a, SHELL_INPUTS));
        try r.put("services", Value{ .array = &.{} });
        try r.put("description", cbor.string(Value.str(p.get("description")) orelse SHELL_DESCRIPTION));
        try r.put("app", cbor.string(b.app));
        return b.record(r.value());
    }
};

/// A field of a record, unless absent or null (JavaScript's `??`).
fn given(v: Value, key: []const u8) ?Value {
    const x = v.get(key) orelse return null;
    return if (x == .null) null else x;
}

const BinFile = struct { name: []const u8, ext: []const u8 };

/// "bin/<x>.wasm" or "bin/<x>.cid", x of [A-Za-z0-9._-]+.
fn binFile(s: []const u8) ?BinFile {
    if (!std.mem.startsWith(u8, s, "bin/")) return null;
    const rest = s[4..];
    const dot = std.mem.lastIndexOfScalar(u8, rest, '.') orelse return null;
    const name = rest[0..dot];
    const ext = rest[dot + 1 ..];
    if (name.len == 0 or (!eql(u8, ext, "wasm") and !eql(u8, ext, "cid"))) return null;
    for (name) |c| if (!(std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '-')) return null;
    return .{ .name = name, .ext = ext };
}

/// A genesis program's name: [a-z0-9][a-z0-9_-]*.
fn isProgramName(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s, 0..) |c, i| {
        const ok = std.ascii.isLower(c) or std.ascii.isDigit(c) or (i > 0 and (c == '_' or c == '-'));
        if (!ok) return false;
    }
    return true;
}

pub const WasmKind = enum { module, component };

/// A wasm module (version 1) or a component (layer 1), by its header.
pub fn wasmKind(b: []const u8) ?WasmKind {
    if (b.len < 8 or !std.mem.eql(u8, b[0..4], "\x00asm")) return null;
    if (std.mem.eql(u8, b[4..8], "\x01\x00\x00\x00")) return .module;
    if (std.mem.eql(u8, b[4..8], "\x0d\x00\x01\x00")) return .component;
    return null;
}

/// An http row's path as served (src/host/manifest.ts appPath): under
/// /<app>/, leading slashes dropped and runs of slashes collapsed; null for
/// anything that could name a path outside it.
pub fn appPath(a: Allocator, app: []const u8, p: []const u8) !?[]const u8 {
    if (p.len > 0 and std.ascii.isAlphabetic(p[0])) {
        var i: usize = 1;
        while (i < p.len and (std.ascii.isAlphanumeric(p[i]) or p[i] == '+' or p[i] == '.' or p[i] == '-')) i += 1;
        if (i < p.len and p[i] == ':') return null;
    }
    for (p) |c| if (c == '\\' or c == 0 or c == '?' or c == '#') return null;
    var lower = try std.ascii.allocLowerString(a, p);
    for ([_][]const u8{ "%2e", "%2f", "%5c", "%00" }) |enc| if (std.mem.indexOf(u8, lower, enc) != null) return null;
    lower = undefined;
    var segs = std.mem.splitScalar(u8, p, '/');
    while (segs.next()) |s| if (eql(u8, s, ".") or eql(u8, s, "..")) return null;
    var out: std.ArrayList(u8) = .empty;
    try out.print(a, "/{s}/", .{app});
    var i: usize = 0;
    while (i < p.len and p[i] == '/') i += 1;
    while (i < p.len) : (i += 1) {
        if (p[i] == '/' and out.items[out.items.len - 1] == '/') continue;
        try out.append(a, p[i]);
    }
    return out.items;
}

/// A row's key as the kernel's table knows it: "<transport> <address as served>[*] <sender>".
fn rowKey(a: Allocator, app: []const u8, r: Value) !?[]const u8 {
    const transport = Value.str(r.get("transport")) orelse "mailbox";
    const address = Value.str(r.get("address")) orelse return null;
    const served = if (eql(u8, transport, "http")) (try appPath(a, app, address)) orelse return null else address;
    const prefix = if (r.get("prefix")) |x| (x == .bool and x.bool) else false;
    return try std.fmt.allocPrint(a, "{s} {s}{s} {s}", .{ transport, served, if (prefix) "*" else "", Value.str(r.get("sender")) orelse "" });
}

fn row(a: Allocator, transport: []const u8, address: []const u8, sender: []const u8, fn_: ?[]const u8) !Value {
    var m = cbor.MapBuilder.init(a);
    try m.put("transport", cbor.string(transport));
    try m.put("address", cbor.string(address));
    try m.put("sender", cbor.string(sender));
    try m.put("program", cbor.string(OVERLAY_ROLE));
    if (fn_) |f| try m.put("fn", cbor.string(f));
    return m.value();
}

fn isTopic(s: []const u8) bool {
    if (s.len == 0 or !std.ascii.isAlphanumeric(s[0])) return false;
    for (s) |c| if (!(std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == ':' or c == '-')) return false;
    return true;
}

/// The rows `config.overlay` derives (src/host/manifest.ts overlayWiring):
/// the app's box from `event` and `$self`, the open http rows /submit and
/// /lookup, and per topic its libp2p rows — all to the role `overlay`.
fn overlayRows(b: *Build, ov: Value, programs: Value) Error![]const Value {
    if (ov != .map) return b.bad("config.overlay: want {{topics, lookups?, gossip?}}", .{});
    if (programs.get(OVERLAY_ROLE) == null) return b.bad("config.overlay: the engine is the role \"overlay\": programs has none", .{});
    const topics = ov.get("topics") orelse Value.null;
    if (topics != .map or topics.map.len == 0) return b.bad("config.overlay: topics: want {{<topic>: <role>}}, at least one", .{});
    var out: std.ArrayList(Value) = .empty;
    try out.append(b.a, try row(b.a, "mailbox", b.app, "event", null));
    try out.append(b.a, try row(b.a, "mailbox", b.app, "$self", null));
    try out.append(b.a, try row(b.a, "http", "/submit", "*", "submit"));
    try out.append(b.a, try row(b.a, "http", "/lookup", "*", "lookup"));
    for (topics.map) |e| {
        const role = Value.str(e.value) orelse "";
        if (!isTopic(e.key) or programs.get(role) == null) return b.bad("config.overlay: topics.{s}: not a topic name and a role in programs", .{e.key});
        try out.append(b.a, try row(b.a, "libp2p", e.key, "*", "submit"));
        try out.append(b.a, try row(b.a, "libp2p", try std.fmt.allocPrint(b.a, "{s}-admit", .{e.key}), "*", "peerAdmit"));
        try out.append(b.a, try row(b.a, "libp2p", try std.fmt.allocPrint(b.a, "{s}-proof", .{e.key}), "*", "peerProof"));
    }
    return out.items;
}

/// Build the app record of the tree `tree` (its CID), whose files `files`
/// reads (`files.read(a, path) → ?content`). Refusals set `why`.
pub fn build(a: Allocator, files: anytype, tree: []const u8, inst: Instance, why: *[]const u8) Error!Built {
    const F = @TypeOf(files);
    const Thunk = struct {
        fn read(ctx: *const anyopaque, al: Allocator, path: []const u8) anyerror!?[]const u8 {
            const f: *const F = @ptrCast(@alignCast(ctx));
            return f.read(al, path);
        }
    };
    var b: Build = .{ .a = a, .files = @ptrCast(&files), .read = Thunk.read, .inst = inst, .app = "", .why = why };
    const text = (try b.file("etc/app.json")) orelse {
        why.* = "the tree has no etc/app.json (an app is a tree with a manifest: skein docs/APPS.md §2)";
        return error.NoManifest;
    };
    const m = dagjson.decode(a, text) catch return b.bad("not JSON", .{});
    if (m != .map) return b.bad("not a JSON object", .{});
    if (!eql(u8, Value.str(m.get("kind")) orelse "", "app")) return b.bad("kind: want \"app\"", .{});
    b.app = Value.str(m.get("name")) orelse return b.bad("name: not text", .{});
    if (b.app.len == 0) return b.bad("name: empty", .{});
    const progs = m.get("programs") orelse Value.null;
    if (progs != .map) return b.bad("programs: want {{role: \"bin/<x>.wasm\" | \"bin/<x>.cid\" | <a program name> | {{code: \"shell\", …}}}}", .{});

    var programs = cbor.MapBuilder.init(a);
    for (progs.map) |e| try programs.put(e.key, cbor.cidv(try b.program(e.key, e.value)));

    // dispatch: the manifest's rows, `transport` defaulted; then what config.overlay derives.
    var rows: std.ArrayList(Value) = .empty;
    if (m.get("dispatch")) |d| if (d != .null) {
        if (d != .array) return b.bad("dispatch: not a list", .{});
        for (d.array) |r| {
            if (r != .map) return b.bad("dispatch: a row is not a map", .{});
            try rows.append(a, if (given(r, "transport") == null) try withField(a, r, "transport", cbor.string("mailbox")) else r);
        }
    };
    const config = m.get("config") orelse Value.null;
    if (config == .map) if (config.get("overlay")) |ov| {
        var have: std.StringHashMapUnmanaged(void) = .empty;
        for (rows.items) |r| if (try rowKey(a, b.app, r)) |k| try have.put(a, k, {});
        for (try overlayRows(&b, ov, progs)) |r| {
            const k = (try rowKey(a, b.app, r)).?;
            if (!have.contains(k)) try rows.append(a, r);
        }
    };

    var rec = cbor.MapBuilder.init(a);
    for (m.map) |e| {
        if (eql(u8, e.key, "programs") or eql(u8, e.key, "dispatch") or eql(u8, e.key, "provides") or eql(u8, e.key, "requires") or eql(u8, e.key, "tree")) continue;
        if (eql(u8, e.key, "state") and inst.state != null) continue;
        try rec.put(e.key, e.value);
    }
    try rec.put("programs", programs.value());
    try rec.put("dispatch", .{ .array = rows.items });
    inline for (.{ "provides", "requires" }) |k| {
        const x: Value = m.get(k) orelse .{ .array = &.{} };
        if (x != .array) return b.bad(k ++ ": not a list", .{});
        try rec.put(k, x);
    }
    try rec.put("tree", cbor.cidv(tree));
    if (inst.state) |s| try rec.put("state", cbor.cidv(s));
    const record = rec.value();
    const app = try b.record(record);
    return .{ .name = b.app, .app = app, .record = record, .blocks = b.blocks.items };
}

/// A copy of map `v` with `key` set to `x`.
fn withField(a: Allocator, v: Value, key: []const u8, x: Value) !Value {
    var m = cbor.MapBuilder.init(a);
    for (v.map) |e| try m.put(e.key, e.value);
    try m.put(key, x);
    return m.value();
}

// ---------------------------------------------------------------- tests

const t = std.testing;

const MemFiles = struct {
    files: []const struct { []const u8, []const u8 },
    pub fn read(f: MemFiles, a: Allocator, path: []const u8) !?[]const u8 {
        _ = a;
        for (f.files) |x| if (eql(u8, x[0], path)) return x[1];
        return null;
    }
};

fn holdsNothing(a: Allocator, c: []const u8) anyerror!bool {
    _ = a;
    _ = c;
    return false;
}

const wasm = "\x00asm\x01\x00\x00\x00";

test "an app record: programs, rows, the tree" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var why: []const u8 = "";
    const manifest =
        \\{"kind":"app","name":"demo","version":"0.1.0","programs":{"main":"bin/demo.wasm"},
        \\ "dispatch":[{"address":"demo","sender":"$owner","program":"main"},
        \\             {"transport":"http","address":"/call","sender":"session","program":"main","fn":"call"}],
        \\ "description":"d"}
    ;
    const files: MemFiles = .{ .files = &.{ .{ "etc/app.json", manifest }, .{ "bin/demo.wasm", wasm } } };
    const tree = try cid.ofGit(a, "tree 0\x00");
    const out = try build(a, files, tree, .{ .has = holdsNothing }, &why);
    try t.expectEqualStrings("demo", out.name);
    try t.expectEqual(@as(usize, 3), out.blocks.len); // module, program record, app record
    try t.expectEqualSlices(u8, out.app, out.blocks[2].cid);
    const prog = try cbor.decode(a, out.blocks[1].bytes);
    try t.expectEqualStrings("demo", Value.str(prog.get("name")).?);
    try t.expectEqualStrings("demo", Value.str(prog.get("app")).?);
    try t.expectEqualStrings("demo (from the system tree)", Value.str(prog.get("description")).?);
    try t.expectEqualSlices(u8, try cid.ofRaw(a, wasm), Value.cidOf(prog.get("code").?.get("wasm")).?);
    const rows = out.record.get("dispatch").?.array;
    try t.expectEqualStrings("mailbox", Value.str(rows[0].get("transport")).?);
    try t.expectEqualStrings("http", Value.str(rows[1].get("transport")).?);
    try t.expectEqual(@as(usize, 0), out.record.get("provides").?.array.len);
    try t.expectEqualSlices(u8, tree, Value.cidOf(out.record.get("tree")).?);
    try t.expect(out.record.get("state") == null);
    // The same record with a state carried over.
    const s = try cid.ofDagCbor(a, "\xa0");
    const again = try build(a, files, tree, .{ .has = holdsNothing, .state = s }, &why);
    try t.expectEqualSlices(u8, s, Value.cidOf(again.record.get("state")).?);
}

test "refusals: no manifest, a missing module, a .cid the instance does not hold" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var why: []const u8 = "";
    const tree = try cid.ofGit(a, "tree 0\x00");
    try t.expectError(error.NoManifest, build(a, MemFiles{ .files = &.{} }, tree, .{ .has = holdsNothing }, &why));
    const m1 = "{\"kind\":\"app\",\"name\":\"x\",\"programs\":{\"p\":\"bin/x.wasm\"}}";
    try t.expectError(error.BadManifest, build(a, MemFiles{ .files = &.{.{ "etc/app.json", m1 }} }, tree, .{ .has = holdsNothing }, &why));
    try t.expectEqualStrings("etc/app.json: programs.p: bin/x.wasm is not in the tree", why);
    const m2 = "{\"kind\":\"app\",\"name\":\"x\",\"programs\":{\"p\":\"bin/x.cid\"}}";
    const c = try cid.format(a, try cid.ofRaw(a, wasm));
    try t.expectError(error.BadManifest, build(a, MemFiles{ .files = &.{ .{ "etc/app.json", m2 }, .{ "bin/x.cid", c } } }, tree, .{ .has = holdsNothing }, &why));
    try t.expectStringEndsWith(why, "which the instance does not hold");
    try t.expectError(error.BadManifest, build(a, MemFiles{ .files = &.{.{ "etc/app.json", "[1]" }} }, tree, .{ .has = holdsNothing }, &why));
    try t.expectError(error.BadManifest, build(a, MemFiles{ .files = &.{.{ "etc/app.json", "{\"kind\":\"app\",\"name\":\"x\",\"programs\":{\"p\":\"bin/x.wasm\"}}" }, .{ "bin/x.wasm", "not wasm" } } }, tree, .{ .has = holdsNothing }, &why));
}

test "an overlay app's derived rows, under the manifest's own" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var why: []const u8 = "";
    const manifest =
        \\{"kind":"app","name":"ov","version":"0.1.0","programs":{"overlay":"bin/o.wasm","topic":"bin/o.wasm"},
        \\ "config":{"overlay":{"topics":{"tm_x":"topic"}}},
        \\ "dispatch":[{"transport":"http","address":"//submit","sender":"*","program":"overlay","fn":"mine"}]}
    ;
    const out = try build(a, MemFiles{ .files = &.{ .{ "etc/app.json", manifest }, .{ "bin/o.wasm", wasm } } }, try cid.ofGit(a, "tree 0\x00"), .{ .has = holdsNothing }, &why);
    const rows = out.record.get("dispatch").?.array;
    // the manifest's /submit (as served /ov/submit) wins over the derived one
    try t.expectEqual(@as(usize, 1 + 3 + 3), rows.len);
    try t.expectEqualStrings("mine", Value.str(rows[0].get("fn")).?);
    try t.expectEqualStrings("event", Value.str(rows[1].get("sender")).?);
    try t.expectEqualStrings("tm_x-proof", Value.str(rows[6].get("address")).?);
    // two roles of one file: one module, one program record (the same record), the app record
    try t.expectEqual(@as(usize, 3), out.blocks.len);
}

test "appPath" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try t.expectEqualStrings("/amm/submit", (try appPath(a, "amm", "/submit")).?);
    try t.expectEqualStrings("/amm/", (try appPath(a, "amm", "/")).?);
    try t.expectEqualStrings("/amm/a/b", (try appPath(a, "amm", "//a//b")).?);
    try t.expect((try appPath(a, "amm", "../x")) == null);
    try t.expect((try appPath(a, "amm", "http://x")) == null);
    try t.expect((try appPath(a, "amm", "/a%2Fb")) == null);
}
