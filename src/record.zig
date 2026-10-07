//! The app record of a tree (skein docs/APPS.md §2, §3): what the owner's
//! `head` message names as the root of `<app>/app`. The same record, byte for
//! byte, as skein's install client builds for the same tree
//! (src/host/install.ts `planInstall`, src/host/manifest.ts `checkManifest`):
//!
//!   {kind: "app", name, version, …every other field of etc/app.json as written (roles among them),
//!    programs: {<role>: <program record CID>},
//!    routes: [<the manifest's routes, `transport` defaulted to "mailbox">,
//!             <the routes config.overlay derives, unless a route has the key>],
//!    filters?: {<the manifest's filters>, lookup: "overlay.lookup" for an overlay
//!               that declares none}   (skein#143; only when any),
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
//! The manifest is checked first by every rule of skein's checkManifest
//! (src/host/manifest.ts, skein#143: names, routes — mailbox and event boxes
//! relative to the app, #128; http paths under /<app>/; libp2p routes exact;
//! filters, handlers, roles; `dispatch`, `reads`, senders refused —
//! interfaces, shapes, config.overlay with topics optional and no prefix
//! declarations, #120, start/stop), with its messages, so a clone the install client would refuse
//! is refused here. The client still reads the manifest out of the stored
//! tree, checks it, rebuilds this record and compares the CID before the
//! root signs the head.
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

// ---------------------------------------------------------------- the manifest's checks
//
// src/host/manifest.ts checkManifest, rule for rule and message for message
// (each problem one line; JSON.stringify where it quotes). The install client
// checks the same manifest; a clone it would refuse is refused here.

/// A stock box, head, program or role name of the instance (manifest.ts RESERVED_NAMES).
const RESERVED_NAMES = [_][]const u8{ "objects", "head", "dispatch", "peers", "grant", "grants", "claim", "subscribe", "routes", "main", "sessions", "wallet", "kernel", "frontdoor", "messagebox", "resolve", "billing", "tick", "reads", "root", "user" };
/// The fields gone, refused (manifest.ts GONE_FIELDS): the form before #77 (#79), and skein#143's.
const GONE_FIELDS = [_][2][]const u8{
    .{ "handler", "the form before #77 is gone (#79): name routes, and write only heads under the app's name" },
    .{ "boxes", "the form before #77 is gone (#79): name routes" },
    .{ "heads", "the form before #77 is gone (#79): an app writes only heads under its own name" },
    .{ "dispatch", "gone (#143): name `routes` ({transport?, address, prefix?, filters?, handler?, …}, no sender)" },
    .{ "reads", "gone (#143): a read is a route with filters and no handler (the last filter answers)" },
};
/// The fields a route does not have (manifest.ts NOT_ROUTE_FIELDS, skein#143).
const NOT_ROUTE_FIELDS = [_][2][]const u8{
    .{ "sender", "gone (#143): a route has no sender — its filters say who a request is from, and `roles` gate functions" },
    .{ "program", "name the handler: \"<role>.<fn>\" (#143)" },
    .{ "fn", "name the handler: \"<role>.<fn>\" (#143)" },
    .{ "filter", "gone (#143): name `filters`, a list (\"kernel.beef\")" },
    .{ "optional", "gone (#143): a route from a provider is a route like any other" },
    .{ "app", "app is set by the install" },
};
const KERNEL_FILTERS = [_][]const u8{ "kernel.brc104", "kernel.beef" };
const TRANSPORTS = [_][]const u8{ "mailbox", "event", "http", "libp2p" };
const TYPES = [_][]const u8{ "string", "int", "ms", "bytes", "cid", "bool", "map", "any" };
/// The fields of `config.overlay` (`status` is refused with its own reason).
const OVERLAY_FIELDS = [_][]const u8{ "topics", "lookups", "gossip", "market", "validator" };
const SHELL_FIELDS = [_][]const u8{ "code", "modules", "support", "description" };

fn oneOf(s: []const u8, set: []const []const u8) bool {
    for (set) |x| if (eql(u8, s, x)) return true;
    return false;
}

/// A field as JavaScript sees it: absent is `undefined`; JSON null is a value.
fn present(v: Value, key: []const u8) bool {
    return v.get(key) != null;
}

fn isMap(v: ?Value) bool {
    const x = v orelse return false;
    return x == .map;
}

/// JavaScript's `\s` (ECMAScript WhiteSpace and LineTerminator).
fn isJsSpace(c: u21) bool {
    return switch (c) {
        0x09...0x0d, 0x20, 0xa0, 0x1680, 0x2000...0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff => true,
        else => false,
    };
}

/// Whether `s` has whitespace or a NUL (`/[\s\0]/`), or also a control character (`/[\s\0-\x1f\x7f]/`).
fn hasSpace(s: []const u8, controls: bool) bool {
    var it = (std.unicode.Utf8View.init(s) catch return false).iterator();
    while (it.nextCodepoint()) |c| {
        if (isJsSpace(c) or c == 0) return true;
        if (controls and (c < 0x20 or c == 0x7f)) return true;
    }
    return false;
}

/// `/^[first][rest]*$/` over ASCII classes.
fn matches(s: []const u8, first: *const fn (u8) bool, rest: *const fn (u8) bool) bool {
    if (s.len == 0 or !first(s[0])) return false;
    for (s[1..]) |c| if (!rest(c)) return false;
    return true;
}
fn lowerDigit(c: u8) bool {
    return std.ascii.isLower(c) or std.ascii.isDigit(c);
}
fn nameRest(c: u8) bool {
    return lowerDigit(c) or c == '.' or c == '_' or c == '-';
}
fn alnum(c: u8) bool {
    return std.ascii.isAlphanumeric(c);
}
fn topicRest(c: u8) bool {
    return alnum(c) or c == '.' or c == '_' or c == ':' or c == '-';
}
fn commandRest(c: u8) bool {
    return alnum(c) or c == '.' or c == '_' or c == '+' or c == '-';
}
fn alpha(c: u8) bool {
    return std.ascii.isAlphabetic(c);
}
fn wordRest(c: u8) bool {
    return alnum(c) or c == '_';
}
fn alphaUnder(c: u8) bool {
    return alpha(c) or c == '_';
}
fn roleRest(c: u8) bool {
    return lowerDigit(c) or c == '_' or c == '-';
}
fn fnRest(c: u8) bool {
    return alnum(c) or c == '_' or c == '.' or c == '-';
}
fn filterChar(c: u8) bool {
    return alnum(c) or c == '_' or c == '-';
}

/// `^[a-z0-9][a-z0-9_-]*$`: a role.
fn isRoleName(s: []const u8) bool {
    return matches(s, lowerDigit, roleRest);
}

/// `^[A-Za-z_][A-Za-z0-9_.-]*$`: a function.
fn isFn(s: []const u8) bool {
    return matches(s, alphaUnder, fnRest);
}

/// `^[A-Za-z0-9_-]+$`: a filter's name.
fn isFilterName(s: []const u8) bool {
    return matches(s, filterChar, filterChar);
}

/// `^[a-z0-9][a-z0-9._-]*$`: an app's name.
fn isName(s: []const u8) bool {
    return matches(s, lowerDigit, nameRest);
}

/// `^[A-Za-z0-9][A-Za-z0-9._:-]*$`: a topic or a lookup service.
fn isTopic(s: []const u8) bool {
    return matches(s, alnum, topicRest);
}

fn digits(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

fn semverPart(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!(alnum(c) or c == '.' or c == '-')) return false;
    return true;
}

/// `^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`.
fn isSemver(s: []const u8) bool {
    var core = s;
    var build_: ?[]const u8 = null;
    if (std.mem.indexOfScalar(u8, s, '+')) |i| {
        core = s[0..i];
        build_ = s[i + 1 ..];
    }
    var pre: ?[]const u8 = null;
    if (std.mem.indexOfScalar(u8, core, '-')) |i| {
        pre = core[i + 1 ..];
        core = core[0..i];
    }
    var parts = std.mem.splitScalar(u8, core, '.');
    var n: usize = 0;
    while (parts.next()) |p| : (n += 1) if (!digits(p)) return false;
    if (n != 3) return false;
    if (pre) |p| if (!semverPart(p)) return false;
    if (build_) |b| if (!semverPart(b)) return false;
    return true;
}

/// `^[a-z0-9][a-z0-9._-]*\/\d+$`: an interface.
fn isInterface(s: []const u8) bool {
    const i = std.mem.indexOfScalar(u8, s, '/') orelse return false;
    return isName(s[0..i]) and digits(s[i + 1 ..]);
}

/// A path in the tree: relative, no "." or ".." segment, no backslash or NUL.
fn isTreePath(v: ?Value) bool {
    const p = Value.str(v) orelse return false;
    if (p.len == 0 or p[0] == '/') return false;
    for (p) |c| if (c == '\\' or c == 0) return false;
    var segs = std.mem.splitScalar(u8, p, '/');
    while (segs.next()) |s| if (s.len == 0 or eql(u8, s, ".") or eql(u8, s, "..")) return false;
    return true;
}

/// A map's entries in JavaScript's order (Object.entries): array-index keys
/// first, ascending, then the rest as written.
fn jsOrder(a: Allocator, m: []const cbor.Entry) ![]const cbor.Entry {
    const index = struct {
        fn of(k: []const u8) ?u32 {
            if (k.len == 0 or k.len > 10 or (k.len > 1 and k[0] == '0')) return null;
            const n = std.fmt.parseInt(u64, k, 10) catch return null;
            return if (n < 0xffffffff) @intCast(n) else null;
        }
    };
    var out: std.ArrayList(cbor.Entry) = .empty;
    for (m) |e| if (index.of(e.key) != null) try out.append(a, e);
    std.mem.sort(cbor.Entry, out.items, {}, struct {
        fn lt(_: void, x: cbor.Entry, y: cbor.Entry) bool {
            return index.of(x.key).? < index.of(y.key).?;
        }
    }.lt);
    for (m) |e| if (index.of(e.key) == null) try out.append(a, e);
    return out.items;
}

/// JSON.stringify of a value; absent is `undefined`.
fn js(a: Allocator, v: ?Value) Error![]const u8 {
    const x = v orelse return "undefined";
    return switch (x) {
        .null => "null",
        .bool => |b| if (b) "true" else "false",
        .int => |i| try std.fmt.allocPrint(a, "{d}", .{i}),
        .float => |f| try std.fmt.allocPrint(a, "{d}", .{f}),
        .string => |s| try quote(a, s),
        else => dagjson.encode(a, x) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => "{…}",
        },
    };
}

fn quote(a: Allocator, s: []const u8) Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.append(a, '"');
    for (s) |c| switch (c) {
        '"' => try out.appendSlice(a, "\\\""),
        '\\' => try out.appendSlice(a, "\\\\"),
        '\n' => try out.appendSlice(a, "\\n"),
        '\r' => try out.appendSlice(a, "\\r"),
        '\t' => try out.appendSlice(a, "\\t"),
        0x08 => try out.appendSlice(a, "\\b"),
        0x0c => try out.appendSlice(a, "\\f"),
        0...0x07, 0x0b, 0x0e...0x1f => try out.print(a, "\\u{x:0>4}", .{c}),
        else => try out.append(a, c),
    };
    try out.append(a, '"');
    return out.items;
}

/// A resolved address, or why it is not one.
const Got = union(enum) { ok: []const u8, bad: []const u8 };

/// An http row's path as served (src/host/manifest.ts appPath): relative to
/// /<app>/ (a leading "/" too), leading slashes dropped and runs of slashes
/// collapsed; refused: anything that could name a path outside that prefix.
pub fn appPathOf(a: Allocator, app: []const u8, p: []const u8) Error!Got {
    if (p.len > 0 and std.ascii.isAlphabetic(p[0])) {
        var i: usize = 1;
        while (i < p.len and (std.ascii.isAlphanumeric(p[i]) or p[i] == '+' or p[i] == '.' or p[i] == '-')) i += 1;
        if (i < p.len and p[i] == ':') return .{ .bad = try std.fmt.allocPrint(a, "{s} is a URL or a scheme, not a path under /{s}/", .{ try quote(a, p), app }) };
    }
    const lower = try std.ascii.allocLowerString(a, p);
    var encoded = false;
    for ([_][]const u8{ "%2e", "%2f", "%5c", "%00" }) |enc| encoded = encoded or std.mem.indexOf(u8, lower, enc) != null;
    for (p) |c| encoded = encoded or c == '\\' or c == 0 or c == '?' or c == '#';
    if (encoded) return .{ .bad = try std.fmt.allocPrint(a, "{s}: a backslash, NUL, query, fragment or an encoded dot or slash", .{try quote(a, p)}) };
    var segs = std.mem.splitScalar(u8, p, '/');
    while (segs.next()) |s| if (eql(u8, s, ".") or eql(u8, s, "..")) return .{ .bad = try std.fmt.allocPrint(a, "{s}: a \".\" or \"..\" segment", .{try quote(a, p)}) };
    var out: std.ArrayList(u8) = .empty;
    try out.print(a, "/{s}/", .{app});
    var i: usize = 0;
    while (i < p.len and p[i] == '/') i += 1;
    while (i < p.len) : (i += 1) {
        if (p[i] == '/' and out.items[out.items.len - 1] == '/') continue;
        try out.append(a, p[i]);
    }
    return .{ .ok = out.items };
}

/// An http row's path as served; null if refused.
pub fn appPath(a: Allocator, app: []const u8, p: []const u8) !?[]const u8 {
    return switch (try appPathOf(a, app, p)) {
        .ok => |x| x,
        .bad => null,
    };
}

/// A mailbox row's box as the kernel's table holds it (#128; manifest.ts
/// appBox): relative to the app — "" or the app's name is the app's box,
/// "x" is `<app>/x`. Refused: an empty, "." or ".." segment, whitespace or a
/// control character, more than 128 bytes resolved.
pub fn appBox(a: Allocator, app: []const u8, b: []const u8) Error!Got {
    if (b.len == 0 or eql(u8, b, app)) return .{ .ok = app };
    if (hasSpace(b, true)) return .{ .bad = try std.fmt.allocPrint(a, "box {s}: whitespace or a control character", .{try quote(a, b)}) };
    var segs = std.mem.splitScalar(u8, b, '/');
    while (segs.next()) |s| if (s.len == 0 or eql(u8, s, ".") or eql(u8, s, ".."))
        return .{ .bad = try std.fmt.allocPrint(a, "box {s}: an empty, \".\" or \"..\" segment (no box outside {s}/)", .{ try quote(a, b), app }) };
    const box = try std.fmt.allocPrint(a, "{s}/{s}", .{ app, b });
    if (box.len > 128) return .{ .bad = try std.fmt.allocPrint(a, "box {s}: more than 128 bytes", .{try quote(a, box)}) };
    return .{ .ok = box };
}

/// A route's address as served (manifest.ts rowAddress): an http path under
/// /<app>/, a box under the app's (mailbox, event), a libp2p name as written.
fn rowAddress(a: Allocator, app: []const u8, r: Value) Error![]const u8 {
    const transport = Value.str(r.get("transport")) orelse "mailbox";
    const address = Value.str(r.get("address")) orelse "";
    const got = if (eql(u8, transport, "http")) try appPathOf(a, app, address) else if (eql(u8, transport, "mailbox") or eql(u8, transport, "event")) try appBox(a, app, address) else Got{ .ok = address };
    return switch (got) {
        .ok => |x| x,
        .bad => address,
    };
}

/// A route's key as the kernel's table knows it (manifest.ts routeKey): "<transport> <address as served>[ prefix]".
fn routeKey(a: Allocator, app: []const u8, r: Value) Error![]const u8 {
    const prefix = if (r.get("prefix")) |x| (x == .bool and x.bool) else false;
    return std.fmt.allocPrint(a, "{s} {s}{s}", .{ Value.str(r.get("transport")) orelse "mailbox", try rowAddress(a, app, r), if (prefix) " prefix" else "" });
}

const Roles = std.StringHashMapUnmanaged(void);

fn isRole(roles: *const Roles, v: ?Value) bool {
    const s = Value.str(v) orelse return false;
    return roles.contains(s);
}

const Handler = struct { role: []const u8, fn_: ?[]const u8 = null };

/// A handler (or a declared filter's function) resolved against the app's
/// programs (manifest.ts handlerOf, skein#143): "<role>.<fn>"; a bare name that
/// is a role — the program, no function named; any other bare name — a
/// function of the app's one program. Null: none of these.
fn handlerOf(v: ?Value, roles: *const Roles) ?Handler {
    const h = Value.str(v) orelse return null;
    if (h.len == 0) return null;
    if (std.mem.indexOfScalar(u8, h, '.')) |dot| if (dot > 0) {
        const role = h[0..dot];
        const f = h[dot + 1 ..];
        return if (roles.contains(role) and isFn(f)) .{ .role = role, .fn_ = f } else null;
    };
    if (roles.contains(h)) return .{ .role = h };
    if (roles.count() == 1 and isFn(h)) {
        var it = roles.keyIterator();
        return .{ .role = it.next().?.*, .fn_ = h };
    }
    return null;
}

/// Why a route is not one (manifest.ts routeProblem, skein#143), checked
/// against the roles, the filters the app declares and its name; or null.
fn routeProblem(a: Allocator, app: []const u8, r: Value, roles: *const Roles, declared: *const Roles) Error!?[]const u8 {
    if (r != .map) return "not a map";
    for (NOT_ROUTE_FIELDS) |f| if (present(r, f[0])) return try std.fmt.allocPrint(a, "{s}: {s}", .{ f[0], f[1] });
    const tv = given(r, "transport");
    const tr = if (tv) |x| Value.str(x) orelse "" else "mailbox";
    if (!oneOf(tr, &TRANSPORTS)) return try std.fmt.allocPrint(a, "transport {s} is not mailbox, event, http or libp2p", .{try js(a, tv)});
    const http = eql(u8, tr, "http");
    const libp2p = eql(u8, tr, "libp2p");
    const address = Value.str(r.get("address")) orelse return "address is not text";
    if (address.len == 0 and (http or libp2p)) return "address is not text";
    const prefix = r.get("prefix");
    if (eql(u8, tr, "mailbox") or eql(u8, tr, "event")) {
        switch (try appBox(a, app, address)) {
            .ok => {},
            .bad => |why| return why,
        }
        if (prefix != null) return try std.fmt.allocPrint(a, "a {s} route has no prefix", .{tr});
    } else if (http) {
        switch (try appPathOf(a, app, address)) {
            .ok => {},
            .bad => |why| return why,
        }
        if (prefix) |x| if (!(x == .bool and x.bool)) return "prefix is true or absent";
    } else {
        if (hasSpace(address, false)) return try std.fmt.allocPrint(a, "address {s} is not a topic or /protocol", .{try quote(a, address)});
        if (prefix != null) return "a libp2p route has no prefix";
    }
    var filters: []const Value = &.{};
    if (given(r, "filters")) |fv| {
        if (fv != .array) return "filters is a list of filter names";
        for (fv.array) |f| if (f != .string) return "filters is a list of filter names";
        filters = fv.array;
    }
    if (filters.len > 0 and eql(u8, tr, "event")) return "an event route has no filters (an event is the host's wiring)";
    for (filters) |fval| {
        const f = fval.string;
        if (std.mem.startsWith(u8, f, "kernel.")) {
            if (!oneOf(f, &KERNEL_FILTERS)) return try std.fmt.allocPrint(a, "filter {s}: the kernel's are kernel.brc104, kernel.beef", .{f});
            continue;
        }
        const dot = std.mem.lastIndexOfScalar(u8, f, '.') orelse {
            if (!declared.contains(f)) return try std.fmt.allocPrint(a, "filter {s}: not one of this app's (its `filters` declare none by that name)", .{f});
            continue;
        };
        if (!isName(f[0..dot]) or !isFilterName(f[dot + 1 ..])) return try std.fmt.allocPrint(a, "filter {s}: not <app>.<filter>", .{try quote(a, f)});
    }
    const hv = r.get("handler") orelse {
        if (!http) return "handler: a mailbox, event or libp2p route names its handler (\"<role>.<fn>\")";
        if (filters.len == 0) return "a read route (no handler) names its filters: the last one answers";
        return null;
    };
    const h = handlerOf(hv, roles) orelse return try std.fmt.allocPrint(a, "handler {s} is not \"<role>.<fn>\" of a role in programs{s}", .{ try js(a, hv), if (roles.count() == 1) ", or a function of the app's one program" else "" });
    if (h.fn_ == null and (http or libp2p)) return try std.fmt.allocPrint(a, "handler {s}: an {s} route names a function (\"<role>.<fn>\")", .{ try js(a, hv), tr });
    return null;
}

/// Why `shape` is not a shape (manifest.ts shapeProblem), or null.
fn shapeProblem(a: Allocator, shape: Value, at: []const u8) Error!?[]const u8 {
    switch (shape) {
        .string => |s| return if (oneOf(s, &TYPES)) null else try std.fmt.allocPrint(a, "{s}: unknown type {s} (string, int, ms, bytes, cid, bool, map, any, [shape], {{key: shape}})", .{ at, try quote(a, s) }),
        .array => |xs| return if (xs.len == 1) try shapeProblem(a, xs[0], try std.fmt.allocPrint(a, "{s}[]", .{at})) else try std.fmt.allocPrint(a, "{s}: an array shape names one element shape", .{at}),
        .map => |m| {
            for (try jsOrder(a, m)) |e| if (try shapeProblem(a, e.value, try std.fmt.allocPrint(a, "{s}.{s}", .{ at, e.key }))) |p| return p;
            return null;
        },
        else => return try std.fmt.allocPrint(a, "{s}: a shape is a type name, [shape] or {{key: shape}}", .{at}),
    }
}

const Problems = struct {
    a: Allocator,
    list: std.ArrayList([]const u8) = .empty,

    fn add(p: *Problems, comptime fmt: []const u8, args: anytype) Error!void {
        try p.list.append(p.a, try std.fmt.allocPrint(p.a, fmt, args));
    }
};

/// A shell program's problems (manifest.ts shellSource), `at` its place.
fn shellProblems(b: *Build, bad: *Problems, p: Value, at: []const u8) Error!void {
    const a = b.a;
    if (!eql(u8, Value.str(p.get("code")) orelse "", "shell")) return bad.add("{s}: a program given as a map is a shell program: {{code: \"shell\", modules, support?}}", .{at});
    for (try jsOrder(a, p.map)) |e| if (!oneOf(e.key, &SHELL_FIELDS)) try bad.add("{s}.{s}: not a field of a shell program (code, modules, support, description)", .{ at, e.key });
    if (p.get("description")) |d| if (d != .string) try bad.add("{s}.description: not text", .{at});
    const mods = p.get("modules");
    if (!isMap(mods)) try bad.add("{s}.modules: want {{<command>: \"bin/<x>.wasm\"}}", .{at}) else {
        for (try jsOrder(a, mods.?.map)) |e| {
            const path = Value.str(e.value);
            if (!matches(e.key, alnum, commandRest)) try bad.add("{s}.modules: {s} is not a command name", .{ at, try quote(a, e.key) })
            else if (path == null or !isShellModule(path.?)) try bad.add("{s}.modules.{s}: {s} is not bin/<x>.wasm", .{ at, e.key, try js(a, e.value) })
            else if ((try b.file(path.?)) == null) try bad.add("{s}.modules.{s}: {s} is not in the tree", .{ at, e.key, path.? });
        }
        for ([_][]const u8{ "brush", "coreutils" }) |need| if (!present(mods.?, need)) try bad.add("{s}.modules: no {s} (the shell is brush over coreutils)", .{ at, need });
    }
    const sup = p.get("support");
    if (sup != null and !isMap(sup)) try bad.add("{s}.support: want {{<command>: {{mount, files, env?}}}}", .{at});
    if (isMap(sup)) for (try jsOrder(a, sup.?.map)) |e| {
        const where = try std.fmt.allocPrint(a, "{s}.support.{s}", .{ at, e.key });
        if (!isMap(mods) or !present(mods.?, e.key)) {
            try bad.add("{s}: {s} is not a command in modules", .{ where, e.key });
            continue;
        }
        const x = e.value;
        if (x != .map) {
            try bad.add("{s}: want {{mount, files, env?}}", .{where});
            continue;
        }
        const mount = Value.str(x.get("mount"));
        const absolute = if (mount) |m| blk: {
            if (m.len == 0 or m[0] != '/') break :blk false;
            var segs = std.mem.splitScalar(u8, m, '/');
            while (segs.next()) |s| if (eql(u8, s, ".") or eql(u8, s, "..")) break :blk false;
            break :blk true;
        } else false;
        if (!absolute) try bad.add("{s}.mount: not an absolute path", .{where});
        const fs = x.get("files");
        if (!isMap(fs)) try bad.add("{s}.files: want {{<path under the mount>: <a file in the tree>}}", .{where}) else for (try jsOrder(a, fs.?.map)) |f| {
            if (!isTreePath(cbor.string(f.key))) try bad.add("{s}.files: {s} is not a relative path", .{ where, try quote(a, f.key) })
            else if (!isTreePath(f.value) or (try b.file(Value.str(f.value).?)) == null) try bad.add("{s}.files.{s}: {s} is not a file in the tree", .{ where, f.key, try js(a, f.value) });
        }
        const env = x.get("env");
        if (env != null and !isMap(env)) try bad.add("{s}.env: want {{<name>: <text>}}", .{where});
        if (isMap(env)) for (try jsOrder(a, env.?.map)) |v| {
            if (!matches(v.key, alphaUnder, wordRest) or v.value != .string) try bad.add("{s}.env.{s}: want a name and text", .{ where, v.key });
        };
    };
}

/// "bin/<x>.wasm", x of [A-Za-z0-9._-]+: a shell's module.
fn isShellModule(s: []const u8) bool {
    const f = binFile(s) orelse return false;
    return eql(u8, f.ext, "wasm");
}

/// A positive whole number of milliseconds (JavaScript's `Number.isInteger(v) && v > 0`).
fn isMs(v: ?Value) bool {
    const x = v orelse return false;
    return switch (x) {
        .int => |i| i > 0,
        .float => |f| f > 0 and @floor(f) == f and std.math.isFinite(f),
        else => false,
    };
}

/// Whether `v` is a map whose only field is `key`, a positive ms.
fn msSetting(v: Value, key: []const u8) bool {
    if (v != .map or !isMs(v.get(key))) return false;
    for (v.map) |e| if (!eql(u8, e.key, key)) return false;
    return true;
}

/// The routes `config.overlay` derives, or its problems (manifest.ts
/// overlayWiring, skein#143): the app's box as an `event` route and a
/// `mailbox` route, the http routes /submit (filter kernel.beef) and /lookup
/// (a read route: the filter `<app>.lookup` answers), and per topic its libp2p
/// routes <topic> (submit, kernel.beef), <topic>-admit, <topic>-proof — all to
/// the role `overlay`. No topics is an overlay that registers them at runtime
/// (#120); `market` and `validator` are the engine's settings, checked; any
/// other field is refused.
fn overlayWiring(a: Allocator, app: []const u8, ov: Value, roles: *const Roles, bad: *Problems) Error!?[]const Value {
    const before = bad.list.items.len;
    const P = "config.overlay: ";
    if (ov != .map) {
        try bad.add(P ++ "want {{topics?, lookups?, gossip?, market?, validator?}}", .{});
        return null;
    }
    if (!roles.contains(OVERLAY_ROLE)) try bad.add(P ++ "the engine is the role \"{s}\": programs has none", .{OVERLAY_ROLE});
    var topics: std.ArrayList([]const u8) = .empty;
    const tv = ov.get("topics");
    if (tv != null and !isMap(tv)) try bad.add(P ++ "topics: want {{<topic>: <role>}}", .{}) else if (tv) |tm| for (try jsOrder(a, tm.map)) |e| {
        if (!isTopic(e.key)) try bad.add(P ++ "topics: {s} is not a topic name", .{try quote(a, e.key)})
        else if (!isRole(roles, e.value)) try bad.add(P ++ "topics.{s}: {s} is not a role in programs", .{ e.key, try js(a, e.value) })
        else try topics.append(a, e.key);
    };
    var unknown: std.ArrayList(u8) = .empty;
    for (try jsOrder(a, ov.map)) |e| if (!oneOf(e.key, &OVERLAY_FIELDS) and !eql(u8, e.key, "status")) {
        if (unknown.items.len > 0) try unknown.appendSlice(a, ", ");
        try unknown.appendSlice(a, e.key);
    };
    if (unknown.items.len > 0) try bad.add(P ++ "{s}: not a field (want topics, lookups, gossip, market, validator; no prefix declarations, #120)", .{unknown.items});
    const lv = ov.get("lookups");
    if (lv != null and !isMap(lv)) try bad.add(P ++ "lookups: want {{<service>: <role> | {{program: <role>, topics?: [<topic>]}}}}", .{});
    if (isMap(lv)) for (try jsOrder(a, lv.?.map)) |e| {
        if (!isTopic(e.key)) {
            try bad.add(P ++ "lookups: {s} is not a service name", .{try quote(a, e.key)});
            continue;
        }
        const l = e.value;
        const role: ?Value = if (l == .string) l else if (l == .map) l.get("program") else null;
        if (!isRole(roles, role)) try bad.add(P ++ "lookups.{s}: program {s} is not a role in programs", .{ e.key, try js(a, role) });
        if (l == .map) if (l.get("topics")) |lt| {
            const ok = lt == .array and for (lt.array) |x| {
                const s = Value.str(x) orelse break false;
                if (!isMap(tv) or !present(tv.?, s)) break false;
            } else true;
            if (!ok) try bad.add(P ++ "lookups.{s}.topics: want a list of the topics the overlay serves", .{e.key});
        };
        if (l == .map) {
            var extra: std.ArrayList(u8) = .empty;
            for (try jsOrder(a, l.map)) |f| if (!eql(u8, f.key, "program") and !eql(u8, f.key, "topics")) {
                if (extra.items.len > 0) try extra.appendSlice(a, ", ");
                try extra.appendSlice(a, f.key);
            };
            if (extra.items.len > 0) try bad.add(P ++ "lookups.{s}: {s}: not a field (want program, topics)", .{ e.key, extra.items });
        }
    };
    if (present(ov, "status")) try bad.add(P ++ "status: gone (#79): statuses are the chain app's (its `status` route); the overlay admits on the chain app's answer", .{});
    if (ov.get("gossip")) |g| {
        const ok = g == .map and for (g.map) |e| {
            if (e.value != .bool or !oneOf(e.key, topics.items)) break false;
        } else true;
        if (!ok) try bad.add(P ++ "gossip: want {{<topic the overlay serves>: true | false}}", .{});
    }
    if (ov.get("market")) |x| if (!msSetting(x, "window")) try bad.add(P ++ "market: want {{window: <ms>}}", .{});
    if (ov.get("validator")) |x| if (!msSetting(x, "every")) try bad.add(P ++ "validator: want {{every: <ms>}}", .{});
    if (bad.list.items.len > before) return null;

    const beef: []const []const u8 = &.{"kernel.beef"};
    var out: std.ArrayList(Value) = .empty;
    try out.append(a, try derivedRoute(a, "event", app, &.{}, OVERLAY_ROLE));
    try out.append(a, try derivedRoute(a, "mailbox", app, &.{}, OVERLAY_ROLE));
    try out.append(a, try derivedRoute(a, "http", "/submit", beef, OVERLAY_ROLE ++ ".submit"));
    try out.append(a, try derivedRoute(a, "http", "/lookup", &.{try std.fmt.allocPrint(a, "{s}.lookup", .{app})}, null));
    for (topics.items) |t_| {
        try out.append(a, try derivedRoute(a, "libp2p", t_, beef, OVERLAY_ROLE ++ ".submit"));
        try out.append(a, try derivedRoute(a, "libp2p", try std.fmt.allocPrint(a, "{s}-admit", .{t_}), &.{}, OVERLAY_ROLE ++ ".peerAdmit"));
        try out.append(a, try derivedRoute(a, "libp2p", try std.fmt.allocPrint(a, "{s}-proof", .{t_}), &.{}, OVERLAY_ROLE ++ ".peerProof"));
    }
    return out.items;
}

fn derivedRoute(a: Allocator, transport: []const u8, address: []const u8, filters: []const []const u8, handler: ?[]const u8) !Value {
    var m = cbor.MapBuilder.init(a);
    try m.put("transport", cbor.string(transport));
    try m.put("address", cbor.string(address));
    if (filters.len > 0) {
        const fs = try a.alloc(Value, filters.len);
        for (filters, fs) |f, *x| x.* = cbor.string(f);
        try m.put("filters", .{ .array = fs });
    }
    if (handler) |h| try m.put("handler", cbor.string(h));
    return m.value();
}

/// What the manifest asks for as installed (skein#143): its routes (the
/// manifest's, `transport` defaulted, then what config.overlay derives) and its
/// filters (as declared, and the derived `lookup`).
const Wiring = struct { routes: []const Value, filters: Value };

/// Check the manifest (manifest.ts checkManifest) → its routes and filters as
/// installed. Every problem is reported, one line each, in checkManifest's order.
fn check(b: *Build, m: Value) Error!Wiring {
    const a = b.a;
    var bad: Problems = .{ .a = a };
    if (!eql(u8, Value.str(m.get("kind")) orelse "", "app")) try bad.add("kind: want \"app\"", .{});
    const name = Value.str(m.get("name")) orelse "";
    if (!isName(name)) try bad.add("name: {s} is not a name ([a-z0-9][a-z0-9._-]*)", .{try js(a, m.get("name"))})
    else if (oneOf(name, &RESERVED_NAMES)) try bad.add("name: {s} is a stock box, head, program or role of the instance", .{name});
    const app = if (name.len > 0) name else "app";
    if (!isSemver(Value.str(m.get("version")) orelse "")) try bad.add("version: {s} is not semver", .{try js(a, m.get("version"))});
    if (m.get("description")) |d| if (d != .string) try bad.add("description: not text", .{});
    if (m.get("config")) |c| if (c != .map) try bad.add("config: not a map", .{});
    for (GONE_FIELDS) |f| if (present(m, f[0])) try bad.add("{s}: {s}", .{ f[0], f[1] });

    // programs
    var roles: Roles = .empty;
    const progs = m.get("programs");
    if (!isMap(progs)) try bad.add("programs: want {{role: \"bin/<x>.wasm\" | \"bin/<x>.cid\" | <an instance program's name> | {{code: \"shell\", modules, support?}}}}", .{}) else for (try jsOrder(a, progs.?.map)) |e| {
        if (!isRoleName(e.key)) {
            try bad.add("programs: {s} is not a role name ([a-z0-9][a-z0-9_-]*)", .{try quote(a, e.key)});
            continue;
        }
        const at = try std.fmt.allocPrint(a, "programs.{s}", .{e.key});
        if (e.value == .map) {
            const n = bad.list.items.len;
            try shellProblems(b, &bad, e.value, at);
            if (bad.list.items.len == n) try roles.put(a, e.key, {});
            continue;
        }
        const s = Value.str(e.value);
        if (s != null and binFile(s.?) != null) {
            if ((try b.file(s.?)) == null) try bad.add("{s}: {s} is not in the tree", .{ at, s.? });
            try roles.put(a, e.key, {});
        } else if (s != null and isProgramName(s.?)) {
            try roles.put(a, e.key, {});
        } else try bad.add("{s}: {s} is not bin/<x>.wasm, bin/<x>.cid, a program name or a shell program", .{ at, try js(a, e.value) });
    }

    // filters (skein#143): the app's functions any route may list
    var declared: Roles = .empty;
    var filters = cbor.MapBuilder.init(a);
    const fv = m.get("filters");
    if (fv != null and !isMap(fv)) try bad.add("filters: want {{<filter>: \"<role>.<fn>\" | \"<fn>\" | \"<role>\"}}", .{});
    if (isMap(fv)) for (try jsOrder(a, fv.?.map)) |e| {
        if (!isFilterName(e.key)) {
            try bad.add("filters: {s} is not a filter name ([A-Za-z0-9_-]+)", .{try quote(a, e.key)});
            continue;
        }
        if (handlerOf(e.value, &roles) == null) {
            try bad.add("filters.{s}: {s} is not \"<role>.<fn>\" of a role in programs, a role, or a function of the app's one program", .{ e.key, try js(a, e.value) });
            continue;
        }
        try declared.put(a, e.key, {});
        try filters.put(e.key, e.value);
    };

    // roles (skein#143): the functions each role gates
    const rlv = m.get("roles");
    if (rlv != null and !isMap(rlv)) try bad.add("roles: want {{<role>: [<fn>…]}}", .{});
    if (isMap(rlv)) for (try jsOrder(a, rlv.?.map)) |e| {
        if (!isRoleName(e.key)) try bad.add("roles: {s} is not a role name ([a-z0-9][a-z0-9_-]*; \"root\" and \"user\" are the standard roles)", .{try quote(a, e.key)})
        else if (e.value != .array or for (e.value.array) |f| {
            if (f != .string or !isFn(f.string)) break true;
        } else false) try bad.add("roles.{s}: want a list of the functions it gates", .{e.key});
    };

    // routes (skein#143)
    var routes: std.ArrayList(Value) = .empty;
    var keys: std.StringHashMapUnmanaged(void) = .empty;
    const rv_ = m.get("routes");
    if (rv_ != null and rv_.? != .array) try bad.add("routes: not a list", .{});
    if (rv_ != null and rv_.? == .array) for (rv_.?.array, 0..) |r, i| {
        if (try routeProblem(a, app, r, &roles, &declared)) |why| {
            try bad.add("routes[{d}]: {s}", .{ i, why });
            continue;
        }
        const route = try withField(a, r, "transport", cbor.string(Value.str(given(r, "transport")) orelse "mailbox"));
        const k = try routeKey(a, app, route);
        if ((try keys.getOrPut(a, k)).found_existing) {
            try bad.add("routes[{d}]: {s} twice", .{ i, k });
            continue;
        }
        try routes.append(a, route);
    };

    // provides, requires
    const pv = m.get("provides");
    if (pv != null and pv.? != .array) try bad.add("provides: not a list", .{});
    if (pv != null and pv.? == .array) for (pv.?.array, 0..) |p, i| {
        const iface = if (p == .map) Value.str(p.get("interface")) else null;
        if (iface == null or !isInterface(iface.?)) {
            try bad.add("provides[{d}]: interface is not <name>/<major>", .{i});
            continue;
        }
        const fns = p.get("functions");
        if (!isMap(fns) or fns.?.map.len == 0) {
            try bad.add("provides[{d}] ({s}): functions is a non-empty map", .{ i, iface.? });
            continue;
        }
        for (try jsOrder(a, fns.?.map)) |f| {
            const at = try std.fmt.allocPrint(a, "provides[{d}].{s}.{s}", .{ i, iface.?, f.key });
            if (!matches(f.key, alpha, wordRest)) try bad.add("{s}: not a function name", .{at});
            const d = f.value;
            if (d != .map or (d.get("writes") orelse Value.null) != .bool) {
                try bad.add("{s}: writes (true | false) is required", .{at});
                continue;
            }
            inline for (.{ "args", "answer" }) |k| if (d.get(k)) |shape| {
                if (try shapeProblem(a, shape, try std.fmt.allocPrint(a, "{s}." ++ k, .{at}))) |why| try bad.list.append(a, why);
            };
        }
    };
    const rq = m.get("requires");
    if (rq != null and rq.? != .array) try bad.add("requires: not a list", .{});
    if (rq != null and rq.? == .array) for (rq.?.array) |r| {
        if (r != .string or !isInterface(r.string)) try bad.add("requires: {s} is not <name>/<major>", .{try js(a, r)});
    };

    // config.overlay: the overlay app's wiring, derived (APPS.md §6), under what the manifest names itself.
    const config = m.get("config");
    if (isMap(config)) if (config.?.get("overlay")) |ov| {
        if (try overlayWiring(a, app, ov, &roles, &bad)) |derived| {
            const have = keys;
            for (derived) |r| if (!have.contains(try routeKey(a, app, r))) try routes.append(a, r);
            // The derived /lookup's filter: the engine's `lookup` (a manifest may name its own).
            if (!declared.contains("lookup")) try filters.put("lookup", cbor.string(OVERLAY_ROLE ++ ".lookup"));
        }
    };

    // start, stop
    inline for (.{ "start", "stop" }) |k| if (m.get(k)) |x| {
        if (x != .map or !isMap(x.get("body"))) try bad.add(k ++ ": want {{body: {{…}}}}", .{});
    };
    if (present(m, "start") or present(m, "stop")) {
        const own = for (routes.items) |r| {
            if (eql(u8, Value.str(r.get("transport")).?, "mailbox") and eql(u8, try rowAddress(a, app, r), name)) break true;
        } else false;
        if (!own) try bad.add("start/stop go into the app's box: routes must have a mailbox route for {s}", .{name});
    }

    if (bad.list.items.len > 0) {
        b.why.* = try std.fmt.allocPrint(a, "etc/app.json: {s}", .{try std.mem.join(a, "; ", bad.list.items)});
        return error.BadManifest;
    }
    return .{ .routes = routes.items, .filters = filters.value() };
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
    const wiring = try check(&b, m);
    b.app = Value.str(m.get("name")).?;

    const progs = m.get("programs").?;
    var programs = cbor.MapBuilder.init(a);
    for (progs.map) |e| try programs.put(e.key, cbor.cidv(try b.program(e.key, e.value)));

    var rec = cbor.MapBuilder.init(a);
    for (m.map) |e| {
        if (eql(u8, e.key, "programs") or eql(u8, e.key, "routes") or eql(u8, e.key, "filters") or eql(u8, e.key, "provides") or eql(u8, e.key, "requires") or eql(u8, e.key, "tree")) continue;
        if (eql(u8, e.key, "state") and inst.state != null) continue;
        try rec.put(e.key, e.value);
    }
    try rec.put("programs", programs.value());
    try rec.put("routes", .{ .array = wiring.routes });
    // skein#143: `filters` only when there are any (as manifest.ts leaves it out).
    if (wiring.filters.map.len > 0) try rec.put("filters", wiring.filters);
    inline for (.{ "provides", "requires" }) |k| try rec.put(k, m.get(k) orelse Value{ .array = &.{} });
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

test "an app record: programs, routes, the tree" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var why: []const u8 = "";
    const manifest =
        \\{"kind":"app","name":"demo","version":"0.1.0","programs":{"main":"bin/demo.wasm"},
        \\ "routes":[{"address":"demo","handler":"main.call"},
        \\           {"transport":"http","address":"/call","filters":["kernel.brc104"],"handler":"call"}],
        \\ "roles":{"root":["call"]},
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
    const routes = out.record.get("routes").?.array;
    try t.expectEqualStrings("mailbox", Value.str(routes[0].get("transport")).?);
    try t.expectEqualStrings("http", Value.str(routes[1].get("transport")).?);
    try t.expectEqualStrings("call", Value.str(routes[1].get("handler")).?);
    try t.expectEqualStrings("call", Value.str(out.record.get("roles").?.get("root").?.array[0]).?);
    try t.expect(out.record.get("filters") == null);
    try t.expect(out.record.get("dispatch") == null);
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
    const m1 = "{\"kind\":\"app\",\"name\":\"x\",\"version\":\"0.1.0\",\"programs\":{\"p\":\"bin/x.wasm\"}}";
    try t.expectError(error.BadManifest, build(a, MemFiles{ .files = &.{.{ "etc/app.json", m1 }} }, tree, .{ .has = holdsNothing }, &why));
    try t.expectEqualStrings("etc/app.json: programs.p: bin/x.wasm is not in the tree", why);
    const m2 = "{\"kind\":\"app\",\"name\":\"x\",\"version\":\"0.1.0\",\"programs\":{\"p\":\"bin/x.cid\"}}";
    const c = try cid.format(a, try cid.ofRaw(a, wasm));
    try t.expectError(error.BadManifest, build(a, MemFiles{ .files = &.{ .{ "etc/app.json", m2 }, .{ "bin/x.cid", c } } }, tree, .{ .has = holdsNothing }, &why));
    try t.expectStringEndsWith(why, "which the instance does not hold");
    try t.expectError(error.BadManifest, build(a, MemFiles{ .files = &.{.{ "etc/app.json", "[1]" }} }, tree, .{ .has = holdsNothing }, &why));
    try t.expectError(error.BadManifest, build(a, MemFiles{ .files = &.{ .{ "etc/app.json", "{\"kind\":\"app\",\"name\":\"x\",\"version\":\"0.1.0\",\"programs\":{\"p\":\"bin/x.wasm\"}}" }, .{ "bin/x.wasm", "not wasm" } } }, tree, .{ .has = holdsNothing }, &why));
}

test "an overlay app's derived routes, under the manifest's own" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var why: []const u8 = "";
    const manifest =
        \\{"kind":"app","name":"ov","version":"0.1.0","programs":{"overlay":"bin/o.wasm","topic":"bin/o.wasm"},
        \\ "config":{"overlay":{"topics":{"tm_x":"topic"},"market":{"window":1000}}},
        \\ "routes":[{"transport":"http","address":"//submit","handler":"overlay.mine"}]}
    ;
    const out = try build(a, MemFiles{ .files = &.{ .{ "etc/app.json", manifest }, .{ "bin/o.wasm", wasm } } }, try cid.ofGit(a, "tree 0\x00"), .{ .has = holdsNothing }, &why);
    const routes = out.record.get("routes").?.array;
    // the manifest's /submit (as served /ov/submit) wins over the derived one
    try t.expectEqual(@as(usize, 1 + 3 + 3), routes.len);
    try t.expectEqualStrings("overlay.mine", Value.str(routes[0].get("handler")).?);
    try t.expectEqualStrings("event", Value.str(routes[1].get("transport")).?);
    try t.expectEqualStrings("overlay", Value.str(routes[1].get("handler")).?);
    try t.expectEqualStrings("mailbox", Value.str(routes[2].get("transport")).?);
    // /lookup: a read route — no handler, the filter <app>.lookup answers; the filter declared as the engine's
    try t.expectEqualStrings("/lookup", Value.str(routes[3].get("address")).?);
    try t.expect(routes[3].get("handler") == null);
    try t.expectEqualStrings("ov.lookup", Value.str(routes[3].get("filters").?.array[0]).?);
    try t.expectEqualStrings("overlay.lookup", Value.str(out.record.get("filters").?.get("lookup")).?);
    // #121: the submit routes decode the BEEF at the kernel's door
    try t.expectEqualStrings("tm_x", Value.str(routes[4].get("address")).?);
    try t.expectEqualStrings("kernel.beef", Value.str(routes[4].get("filters").?.array[0]).?);
    try t.expectEqualStrings("tm_x-proof", Value.str(routes[6].get("address")).?);
    try t.expectEqualStrings("overlay.peerProof", Value.str(routes[6].get("handler")).?);
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

/// A tree of the manifest and a wasm module at every path its programs name.
fn treeOf(a: Allocator, manifest: []const u8) !MemFiles {
    var files: std.ArrayList(struct { []const u8, []const u8 }) = .empty;
    try files.append(a, .{ "etc/app.json", manifest });
    const m = try dagjson.decode(a, manifest);
    if (m.get("programs")) |ps| if (ps == .map) for (ps.map) |e| if (Value.str(e.value)) |path| try files.append(a, .{ path, wasm });
    return .{ .files = files.items };
}

fn refusal(a: Allocator, manifest: []const u8) ![]const u8 {
    var why: []const u8 = "";
    try t.expectError(error.BadManifest, build(a, try treeOf(a, manifest), try cid.ofGit(a, "tree 0\x00"), .{ .has = holdsNothing }, &why));
    return why;
}

test "skein-amm 0.7.1's manifest: routes, filters, roles; an overlay with no topics" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var why: []const u8 = "";
    const manifest = @embedFile("testdata/amm-app.json");
    const out = build(a, try treeOf(a, manifest), try cid.ofGit(a, "tree 0\x00"), .{ .has = holdsNothing }, &why) catch |e| {
        std.debug.print("{s}\n", .{why});
        return e;
    };
    try t.expectEqualStrings("amm", out.name);
    const routes = out.record.get("routes").?.array;
    // its 13 routes, then the derived: the box as event and mailbox, /submit, /lookup
    try t.expectEqual(@as(usize, 13 + 4), routes.len);
    try t.expectEqualStrings("register", Value.str(routes[0].get("address")).?);
    try t.expectEqualStrings("mailbox", Value.str(routes[0].get("transport")).?);
    try t.expectEqualStrings("kernel.beef", Value.str(routes[1].get("filters").?.array[0]).?);
    try t.expectEqualStrings("/", Value.str(routes[12].get("address")).?);
    try t.expectEqualStrings("www", Value.str(routes[12].get("root")).?);
    try t.expectEqualStrings("amm", Value.str(routes[13].get("address")).?);
    try t.expectEqualStrings("event", Value.str(routes[13].get("transport")).?);
    try t.expectEqualStrings("/lookup", Value.str(routes[16].get("address")).?);
    const filters = out.record.get("filters").?;
    try t.expectEqualStrings("amm-p2p.serve", Value.str(filters.get("page")).?);
    try t.expectEqualStrings("overlay.lookup", Value.str(filters.get("lookup")).?);
    try t.expectEqualStrings("register", Value.str(out.record.get("roles").?.get("root").?.array[0]).?);
    try t.expectEqualStrings("chain/1", Value.str(out.record.get("requires").?.array[0]).?);
    try t.expectEqual(@as(usize, 3), out.record.get("provides").?.array.len);
}

test "config.overlay: no prefix declarations (#120), topics optional, its fields checked" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const head = "{\"kind\":\"app\",\"name\":\"ov\",\"version\":\"0.1.0\",\"programs\":{\"overlay\":\"bin/o.wasm\",\"tm\":\"bin/t.wasm\"},\"config\":{\"overlay\":";
    try t.expectEqualStrings("etc/app.json: config.overlay: prefixes: not a field (want topics, lookups, gossip, market, validator; no prefix declarations, #120)", try refusal(a, head ++ "{\"prefixes\":{\"tm_\":\"tm\"}}}}"));
    try t.expectEqualStrings("etc/app.json: config.overlay: topics: want {<topic>: <role>}", try refusal(a, head ++ "{\"topics\":[]}}}"));
    try t.expectEqualStrings("etc/app.json: config.overlay: topics.tm_x: \"nope\" is not a role in programs", try refusal(a, head ++ "{\"topics\":{\"tm_x\":\"nope\"}}}}"));
    try t.expectEqualStrings("etc/app.json: config.overlay: status: gone (#79): statuses are the chain app's (its `status` route); the overlay admits on the chain app's answer", try refusal(a, head ++ "{\"status\":{}}}}"));
    try t.expectEqualStrings("etc/app.json: config.overlay: gossip: want {<topic the overlay serves>: true | false}", try refusal(a, head ++ "{\"gossip\":{\"tm_x\":true}}}}"));
    try t.expectEqualStrings("etc/app.json: config.overlay: lookups.ls_x.topics: want a list of the topics the overlay serves", try refusal(a, head ++ "{\"lookups\":{\"ls_x\":{\"program\":\"tm\",\"topics\":[\"tm_y\"]}}}}}"));
    try t.expectEqualStrings("etc/app.json: config.overlay: market: want {window: <ms>}; config.overlay: validator: want {every: <ms>}", try refusal(a, head ++ "{\"market\":{\"window\":0},\"validator\":{\"every\":1,\"x\":2}}}}"));
    try t.expectEqualStrings("etc/app.json: config.overlay: want {topics?, lookups?, gossip?, market?, validator?}", try refusal(a, head ++ "[]}}"));
    // no topics: the box routes, /submit and /lookup
    inline for (.{ "{}}}", "{\"topics\":{}}}}" }) |rest| {
        var why: []const u8 = "";
        const out = try build(a, try treeOf(a, head ++ rest), try cid.ofGit(a, "tree 0\x00"), .{ .has = holdsNothing }, &why);
        const routes = out.record.get("routes").?.array;
        try t.expectEqual(@as(usize, 4), routes.len);
        try t.expectEqualStrings("ov", Value.str(routes[0].get("address")).?);
        try t.expectEqualStrings("event", Value.str(routes[0].get("transport")).?);
        try t.expectEqualStrings("mailbox", Value.str(routes[1].get("transport")).?);
        try t.expectEqualStrings("kernel.beef", Value.str(routes[2].get("filters").?.array[0]).?);
    }
}

test "boxes are relative to the app (#128)" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try t.expectEqualStrings("amm", (try appBox(a, "amm", "")).ok);
    try t.expectEqualStrings("amm", (try appBox(a, "amm", "amm")).ok);
    try t.expectEqualStrings("amm/submit", (try appBox(a, "amm", "submit")).ok);
    try t.expectEqualStrings("amm/a/b", (try appBox(a, "amm", "a/b")).ok);
    try t.expectEqualStrings("box \"a//b\": an empty, \".\" or \"..\" segment (no box outside amm/)", (try appBox(a, "amm", "a//b")).bad);
    try t.expect((try appBox(a, "amm", "../x")) == .bad);
    try t.expect((try appBox(a, "amm", "x/")) == .bad);
    try t.expect((try appBox(a, "amm", "/x")) == .bad);
    try t.expectEqualStrings("box \"a b\": whitespace or a control character", (try appBox(a, "amm", "a b")).bad);
    try t.expect((try appBox(a, "amm", "a\u{a0}b")) == .bad);
    try t.expect((try appBox(a, "amm", "a\x7fb")) == .bad);
    try t.expect((try appBox(a, "amm", "x" ** 124)) == .ok);
    try t.expectStringEndsWith((try appBox(a, "amm", "x" ** 125)).bad, ": more than 128 bytes");
    const head = "{\"kind\":\"app\",\"name\":\"amm\",\"version\":\"0.1.0\",\"programs\":{\"p\":\"bin/p.wasm\"},\"routes\":";
    // "" and the app's name are one box: the same key twice
    try t.expectEqualStrings("etc/app.json: routes[1]: mailbox amm twice", try refusal(a, head ++ "[{\"address\":\"\",\"handler\":\"p\"},{\"address\":\"amm\",\"handler\":\"p\"}]}"));
    try t.expectEqualStrings("etc/app.json: routes[0]: box \"../x\": an empty, \".\" or \"..\" segment (no box outside amm/)", try refusal(a, head ++ "[{\"address\":\"../x\",\"handler\":\"p\"}]}"));
    // an event route and a mailbox route at one box are two keys
    var why: []const u8 = "";
    _ = try build(a, try treeOf(a, head ++ "[{\"transport\":\"event\",\"address\":\"\",\"handler\":\"p\"},{\"address\":\"amm\",\"handler\":\"p\"}],\"start\":{\"body\":{}}}"), try cid.ofGit(a, "tree 0\x00"), .{ .has = holdsNothing }, &why);
    try t.expectEqualStrings("etc/app.json: start/stop go into the app's box: routes must have a mailbox route for amm", try refusal(a, head ++ "[{\"transport\":\"event\",\"address\":\"amm\",\"handler\":\"p\"}],\"stop\":{\"body\":{}}}"));
}

test "the #143 shape: dispatch, reads, senders and $names refused; routes, filters, roles checked" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const head = "{\"kind\":\"app\",\"name\":\"x\",\"version\":\"0.1.0\",\"programs\":{\"p\":\"bin/p.wasm\"},";
    try t.expectEqualStrings("etc/app.json: dispatch: gone (#143): name `routes` ({transport?, address, prefix?, filters?, handler?, …}, no sender)", try refusal(a, head ++ "\"dispatch\":[{\"address\":\"\",\"sender\":\"$owner\",\"program\":\"p\"}]}"));
    try t.expectEqualStrings("etc/app.json: reads: gone (#143): a read is a route with filters and no handler (the last filter answers)", try refusal(a, head ++ "\"reads\":[]}"));
    try t.expectEqualStrings("etc/app.json: routes[0]: sender: gone (#143): a route has no sender — its filters say who a request is from, and `roles` gate functions", try refusal(a, head ++ "\"routes\":[{\"address\":\"\",\"sender\":\"$owner\",\"handler\":\"p\"}]}"));
    try t.expectEqualStrings("etc/app.json: routes[0]: program: name the handler: \"<role>.<fn>\" (#143)", try refusal(a, head ++ "\"routes\":[{\"address\":\"\",\"program\":\"p\"}]}"));
    try t.expectEqualStrings("etc/app.json: routes[0]: filter: gone (#143): name `filters`, a list (\"kernel.beef\")", try refusal(a, head ++ "\"routes\":[{\"address\":\"\",\"handler\":\"p\",\"filter\":\"beef\"}]}"));
    try t.expectEqualStrings("etc/app.json: routes[0]: optional: gone (#143): a route from a provider is a route like any other", try refusal(a, head ++ "\"routes\":[{\"address\":\"\",\"handler\":\"p\",\"optional\":true}]}"));
    try t.expectEqualStrings("etc/app.json: routes[0]: transport \"session\" is not mailbox, event, http or libp2p", try refusal(a, head ++ "\"routes\":[{\"transport\":\"session\",\"address\":\"\",\"handler\":\"p\"}]}"));
    try t.expectEqualStrings("etc/app.json: routes[0]: an event route has no filters (an event is the host's wiring)", try refusal(a, head ++ "\"routes\":[{\"transport\":\"event\",\"address\":\"\",\"filters\":[\"kernel.beef\"],\"handler\":\"p\"}]}"));
    try t.expectEqualStrings("etc/app.json: routes[0]: filter kernel.x: the kernel's are kernel.brc104, kernel.beef", try refusal(a, head ++ "\"routes\":[{\"address\":\"\",\"filters\":[\"kernel.x\"],\"handler\":\"p\"}]}"));
    try t.expectEqualStrings("etc/app.json: routes[0]: filter q: not one of this app's (its `filters` declare none by that name)", try refusal(a, head ++ "\"routes\":[{\"address\":\"\",\"filters\":[\"q\"],\"handler\":\"p\"}]}"));
    try t.expectEqualStrings("etc/app.json: routes[0]: filter \"Bad.q\": not <app>.<filter>", try refusal(a, head ++ "\"routes\":[{\"address\":\"\",\"filters\":[\"Bad.q\"],\"handler\":\"p\"}]}"));
    try t.expectEqualStrings("etc/app.json: routes[0]: handler: a mailbox, event or libp2p route names its handler (\"<role>.<fn>\")", try refusal(a, head ++ "\"routes\":[{\"address\":\"\"}]}"));
    try t.expectEqualStrings("etc/app.json: routes[0]: a read route (no handler) names its filters: the last one answers", try refusal(a, head ++ "\"routes\":[{\"transport\":\"http\",\"address\":\"/x\"}]}"));
    try t.expectEqualStrings("etc/app.json: routes[0]: handler \"q.f\" is not \"<role>.<fn>\" of a role in programs, or a function of the app's one program", try refusal(a, head ++ "\"routes\":[{\"address\":\"\",\"handler\":\"q.f\"}]}"));
    try t.expectEqualStrings("etc/app.json: routes[0]: handler \"p\": an http route names a function (\"<role>.<fn>\")", try refusal(a, head ++ "\"routes\":[{\"transport\":\"http\",\"address\":\"/x\",\"handler\":\"p\"}]}"));
    try t.expectEqualStrings("etc/app.json: routes[0]: a libp2p route has no prefix", try refusal(a, head ++ "\"routes\":[{\"transport\":\"libp2p\",\"address\":\"tm_x\",\"prefix\":true,\"handler\":\"p.f\"}]}"));
    try t.expectEqualStrings("etc/app.json: routes[0]: \"../y\": a \".\" or \"..\" segment", try refusal(a, head ++ "\"routes\":[{\"transport\":\"http\",\"address\":\"../y\",\"handler\":\"p.f\"}]}"));
    try t.expectEqualStrings("etc/app.json: routes[1]: http /x/ prefix twice", try refusal(a, head ++ "\"routes\":[{\"transport\":\"http\",\"address\":\"/\",\"prefix\":true,\"handler\":\"p.f\"},{\"transport\":\"http\",\"address\":\"//\",\"prefix\":true,\"handler\":\"g\"}]}"));
    try t.expectEqualStrings("etc/app.json: filters: \"a.b\" is not a filter name ([A-Za-z0-9_-]+); filters.q: \"z.f\" is not \"<role>.<fn>\" of a role in programs, a role, or a function of the app's one program", try refusal(a, head ++ "\"filters\":{\"a.b\":\"p.f\",\"q\":\"z.f\"}}"));
    try t.expectEqualStrings("etc/app.json: roles: \"Admin\" is not a role name ([a-z0-9][a-z0-9_-]*; \"root\" and \"user\" are the standard roles); roles.user: want a list of the functions it gates", try refusal(a, head ++ "\"roles\":{\"Admin\":[\"f\"],\"user\":[1]}}"));
    try t.expectEqualStrings("etc/app.json: name: root is a stock box, head, program or role of the instance", try refusal(a, "{\"kind\":\"app\",\"name\":\"root\",\"version\":\"1.0.0\",\"programs\":{\"p\":\"bin/o.wasm\"}}"));
    try t.expectEqualStrings("etc/app.json: programs: \"P\" is not a role name ([a-z0-9][a-z0-9_-]*)", try refusal(a, "{\"kind\":\"app\",\"name\":\"x\",\"version\":\"1.0.0\",\"programs\":{\"P\":\"bin/o.wasm\"}}"));
    // A read route: filters and no handler; an own filter; a role's function gated
    var why: []const u8 = "";
    const out = try build(a, try treeOf(a, head ++ "\"filters\":{\"page\":\"p.serve\"},\"roles\":{\"root\":[\"wipe\"]},\"routes\":[{\"transport\":\"http\",\"address\":\"/\",\"prefix\":true,\"filters\":[\"page\"],\"root\":\"www\"},{\"address\":\"\",\"filters\":[\"other.f\"],\"handler\":\"wipe\"}]}"), try cid.ofGit(a, "tree 0\x00"), .{ .has = holdsNothing }, &why);
    const routes = out.record.get("routes").?.array;
    try t.expectEqual(@as(usize, 2), routes.len);
    try t.expect(routes[0].get("handler") == null);
    try t.expectEqualStrings("www", Value.str(routes[0].get("root")).?);
    try t.expectEqualStrings("p.serve", Value.str(out.record.get("filters").?.get("page")).?);
}

test "the rest of checkManifest: names, interfaces, shapes" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try t.expectEqualStrings("etc/app.json: kind: want \"app\"; name: \"X\" is not a name ([a-z0-9][a-z0-9._-]*); version: \"1.0\" is not semver; programs: want {role: \"bin/<x>.wasm\" | \"bin/<x>.cid\" | <an instance program's name> | {code: \"shell\", modules, support?}}", try refusal(a, "{\"name\":\"X\",\"version\":\"1.0\"}"));
    try t.expectEqualStrings("etc/app.json: name: wallet is a stock box, head, program or role of the instance", try refusal(a, "{\"kind\":\"app\",\"name\":\"wallet\",\"version\":\"1.0.0-rc.1+b\",\"programs\":{}}"));
    const head = "{\"kind\":\"app\",\"name\":\"x\",\"version\":\"0.1.0\",\"programs\":{\"p\":\"bin/p.wasm\"},";
    try t.expectEqualStrings("etc/app.json: boxes: the form before #77 is gone (#79): name routes", try refusal(a, head ++ "\"boxes\":[]}"));
    try t.expectEqualStrings("etc/app.json: provides[0].a/1.f: writes (true | false) is required; provides[0].a/1.g.args.k: unknown type \"text\" (string, int, ms, bytes, cid, bool, map, any, [shape], {key: shape}); requires: \"b\" is not <name>/<major>", try refusal(a, head ++ "\"provides\":[{\"interface\":\"a/1\",\"functions\":{\"f\":{},\"g\":{\"writes\":true,\"args\":{\"k\":\"text\"}}}}],\"requires\":[\"b\"]}"));
    try t.expectEqualStrings("etc/app.json: programs.sh.modules.brush: bin/brush.wasm is not in the tree; programs.sh.modules: no coreutils (the shell is brush over coreutils)", try refusal(a, "{\"kind\":\"app\",\"name\":\"x\",\"version\":\"0.1.0\",\"programs\":{\"sh\":{\"code\":\"shell\",\"modules\":{\"brush\":\"bin/brush.wasm\"}}}}"));
}
