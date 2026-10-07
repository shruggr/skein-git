# Test packs

`deltas.pack` and `refdelta.pack` are the same nine objects (three commits,
three trees, three versions of one file `f.txt` that grows: 60, 70 and 80
lines), packed by git 2.55:

```
git rev-list --objects --all | git pack-objects --stdout -q                         > deltas.pack     # ofs-deltas
git rev-list --objects --all | git pack-objects --stdout -q --no-delta-base-offset  > refdelta.pack   # ref-deltas
```

Authored and committed by `skein <skein@test>` at 2026-10-03T12:00:00Z, so
the ids are fixed:

| id | object |
|---|---|
| `ba40a44f457769933fb16753589b6317354d6d49` | commit "three" (tree `a930a7aa1c9194b284b33adaaf354e258b59e01f`) |
| `d76ad08aa064a9f1d6bc27e48ff9cacf1b96cfb4` | commit "two" |
| `0ef3ea703f1f84ab7324ff135b776154ac470d36` | commit "one" |
| `bf45ebab0d463d141e1c4f424897b679d5dcaa2f` | `f.txt` at "three", stored whole |
| `75ff566337d9ffe02ebff4535fc07c78fc594c27`, `a8eb7c297899d1c45ee3d4ebd9ecc877644cd982` | `f.txt` at "two" and "one", each a delta of it |

# Manifests

`amm-app.json` is shruggr/skein-amm 0.7.1's `etc/app.json` (commit
`00a731b`), as written: skein's routes, filters and roles (shruggr/skein#143)
— mailbox routes relative to the app (`"register"`, `"submit"` with
`filters: ["kernel.beef"]`, `"amm-p2p"`, #128), http routes with a handler
and read routes (filters, no handler; `/` a prefix with `root` and `index`
settings), libp2p routes, declared filters, `roles: {root: [...]}`, an
overlay with no topics (`config.overlay` names lookups only, #120),
`requires: ["chain/1"]`. src/record.zig builds its record.
