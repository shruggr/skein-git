# skein-git

The git app for a [skein](https://github.com/shruggr/skein): it clones one
commit of a git repository into the instance's store, by hash, inside the
VM, and builds the app record of its tree. With it an app is deployed from a
page by two owner-signed messages: the clone, then the install (`head`,
`dispatch`, `start`). Version **0.1.2**.

## What it is

One program, `bin/git.wasm`, interface `git/1`, one function:

| function | args | answer |
|---|---|---|
| `git.clone` (`writes: true`) | `{url, hash}` | `{tree, app}` |

It is reached in one box, `git`, from the owner (`$owner`). `url` is an
http(s) git repository; `hash` is a commit id (40 hex digits). The answer is
a message to the sender in box `git` (when the address book reaches the
sender) and, either way, the request thread's result:

```
{fn: "git.clone", args: {url: "https://github.com/shruggr/skein-onboard", hash: "e142f8ea203a5846ac2de9d4c319669c59463af9"}}
→ {fn, request, replyTo, result: {tree: <cid>, app: <cid>}}
→ {fn, request, replyTo, error: {code, message}}
```

What happens, in the instance's log (one thread, three steps):

1. The call is checked, and `GET <url>/info/refs?service=git-upload-pack`
   (`Git-Protocol: version=2`) is recorded as a `fetch` intention (`sk.fetch`,
   shruggr/skein#126): the runtime sends it, signed with the instance's key,
   to its HTTP proxy. The thread rests on the proxy's signed answer.
2. On the advertisement (a protocol version 2 server offering shallow
   fetches), `POST <url>/git-upload-pack` is emitted: `command=fetch`,
   `want <hash>`, `deepen 1`, `ofs-delta`, `no-progress`, `done` — no
   `thin-pack`, so the pack is self-contained.
3. On the response, the pack is taken from its `packfile` section (side-band
   1), at most 32 MiB; it is unpacked (ofs- and ref-deltas applied; at most
   256 MiB and 200 000 objects); the commit whose id is `hash` is found and
   its tree walked. Every id is computed from the bytes, never read from the
   pack, and every object the commit names must be in it: what is kept is
   what the hash commits to. The commit, its trees and its blobs are put as
   git-raw blocks (CIDv1 git-raw sha1 = the git id). The app record is built
   from the tree's `etc/app.json`; its modules and program records are put;
   the commit, the tree and the app record are kept; the answer goes out.

The pack itself is not stored: only the objects the commit reaches. (The
HTTP proxy's answer, which carries it, is an entry of the log, as every
service's answer is: replay reads it from there and never asks the
network.)

**The app record** is the one skein's install client builds for the same
tree, byte for byte (skein `src/host/install.ts`, `docs/APPS.md` §2): the
manifest as written, `programs` → program records (`bin/<x>.wasm` a raw
module block, `bin/<x>.cid` a module the instance holds, a genesis
program's name, or a shell program `{code: "shell", modules, support?}`),
`dispatch` with `transport` defaulted and an overlay's derived rows,
`provides`/`requires` defaulted to `[]`, `tree`, and the installed app's
`state` carried over. The manifest is checked first by every rule of
skein's `checkManifest` (`src/host/manifest.ts`), with its messages: mailbox
boxes relative to the app (`""` or the app's name is its box, `"x"` is
`<app>/x`, #128), `config.overlay` with `topics` optional and no prefix
declarations (#120). The client checks the manifest, rebuilds the record
from the stored tree and compares the CID before the owner signs the head.

**What it may do.** It writes no head (its scope is `git/…`, and it uses
none): blocks are content-addressed and unscoped, so keeping them grants
nothing and mounts nothing. Only the owner's `head` message makes the tree
an app, and only the owner's `dispatch` messages give it rows. It has no
`$self` row and sends nothing to its own instance.

Error codes: `bad-request` (not `{fn, args}`), `unknown-fn`, `bad-args` (the
url or the hash is not one), `unreachable` (the HTTP proxy could not
reach the url), `not-git` (an HTTP status other than 200, or not a protocol
version 2 server with shallow fetches), `not-found` (the server does not
hold the commit), `too-large` (the pack is over 32 MiB, or unpacks to more
than allowed), `mismatch` (the pack is corrupt, or does not hold the commit
or what it names), `no-manifest`, `bad-manifest`, `failed`.

Only `sha1` repositories; only commit ids (not refs, tags or tree ids).
Submodules (gitlinks) are entries of a tree, not followed. `push` is later.

## Use it

```
skein-host install https://github.com/shruggr/skein-git#v0.1.2 --instance <handle>
```

Then, as the owner, `{fn: "git.clone", args: {url, hash}}` to box `git`,
and the install by the kernel's operations: `head {name: "<app>/app",
tree: <app>}`, a `dispatch` per row, `start` (skein `docs/APPS.md` §3).

The manifest, `etc/app.json` (description left out):

```json
{
  "kind": "app",
  "name": "git",
  "version": "0.1.2",
  "programs": { "git": "bin/git.wasm" },
  "provides": [{ "interface": "git/1", "functions": {
    "clone": { "writes": true, "args": { "url": "string", "hash": "string" },
      "answer": { "tree": "cid", "app": "cid" } } } }],
  "requires": [],
  "dispatch": [{ "address": "git", "sender": "$owner", "program": "git" }]
}
```

## Build and test

Zig 0.16.0 (`mise.toml`).

```
zig build          # zig-out/bin/git.wasm
zig build bin      # the same, into bin/git.wasm (committed; the build is reproducible)
zig build test     # pkt-lines, packs and deltas, trees, the app record (natively)
```

| file | what |
|---|---|
| `src/main.zig` | the handler: the three steps, the answer |
| `src/pkt.zig` | pkt-lines; the protocol v2 advertisement, fetch request and response |
| `src/pack.zig` | a packfile read whole: objects, ofs- and ref-deltas, the trailer |
| `src/tree.zig` | a commit's tree: entries, files by path, what it reaches |
| `src/record.zig` | the app record and its program records |
| `src/testdata/` | two small packs (ofs- and ref-deltas), how they were made |

zlib and SHA-1 are Zig's standard library; CIDs, dag-cbor and DAG-JSON are
the SDK's.

skein runs this app end to end in `kernel-zig/equiv/git-clone.ts` (a pinned
commit of this repo): a local repository served by `git http-backend`, the
owner's clone, the record rebuilt by the install client with the same CID,
the install, the app running, and the refusals (a hash not held, a server
sending another commit's pack, a bad URL, no repository, no manifest), the
store replayed.

## Docs

| what | where |
|---|---|
| the program's contract | `src/main.zig` |
| apps, the app record, install (the two paths) | skein `docs/APPS.md` §2, §3 |
| the fetch intention | skein `docs/MESSAGES.md` "Intentions: deadline and fetch" |

## Versions

| | |
|---|---|
| this app | 0.1.2 (tag `v0.1.2`): the manifest checked by every rule of skein's `checkManifest` (an overlay may list no topics, #120; boxes relative to the app, #128). 0.1.1: fetches by the `fetch` intention (`sk.fetch`; the address book has no roles, shruggr/skein#126) |
| skein-sdk | v0.7.1, by tag tarball and hash in `build.zig.zon` (`cbor`, `sk`, `app`, `dagjson`; no wallet) |
| skein | log format 8; the fetch intention's `maxBytes` (#91, #126); skein's equivs pin this repo by commit |

## Contributing

Work is tracked in shruggr/skein; start at issue
[#31](https://github.com/shruggr/skein/issues/31). MIT, as skein.
