# Test fixtures

Real firmware dumps from the research directory (Honor 90 Lite CRT-NX1).
Do not delete: the golden tests assert byte-identical patch output against
`lk_71_a_patched.bin` / `lk_9_a_patched.bin`.

| File | Source | SHA-256 |
|---|---|---|
| `lk_71_a_original.bin` | `lk-a-original.bin` (MagicOS 7.1, 7.1.0.157 C431E2R2P2) | `552a1623c30146c493edd793e00117d05df7a707f181f30f2b08c6dd1462ff2d` |
| `lk_71_a_patched.bin` | `lk-patched.bin` (proven patched result) | `b40207b4d7a0ca1ce0c553cb9e8bf747020007ea303497308ec3ead1f5b24d2d` |
| `lk_9_a_original.bin` | `lk-9-fresh-backup/lk_a.now` (MagicOS 9, 9.0.0.202 C431E9R2P3) | `91476bfab95be519c183703d4cbaa1a09dd147dc579177c05668653be3554368` |
| `lk_9_a_patched.bin` | `lk-MagicOS9_FB-unlock-candidate.bin` (verified candidate) | `ec2867329c58f1d8dade8d3eb89c9a86688e27d0e2b4a1e75a95b53b6c1f0ef5` |
| `seccfg_locked.bin` | `seccfg-original.bin` (state 0x01) | `1a0c3e67c740f8313ea2463b1a90d59fedb1dd795dc8dfccbd36332e2fc5fdf3` |
| `seccfg_unlocked.bin` | `seccfg-unlock-readback.bin` (state 0x03) | `3eee6334e2f895fa9561e01b7a1db3ac11783823eaa56bb6afdbfc1ebab814e4` |

Regenerate from the parent research directory:

```bash
cp ../lk-a-original.bin lk_71_a_original.bin
cp ../lk-patched.bin lk_71_a_patched.bin
cp ../lk-9-fresh-backup/lk_a.now lk_9_a_original.bin
cp ../lk-MagicOS9_FB-unlock-candidate.bin lk_9_a_patched.bin
cp ../seccfg-original.bin seccfg_locked.bin
cp ../seccfg-unlock-readback.bin seccfg_unlocked.bin
```

`fake_adb.sh` is the hermetic device stand-in used by `e2e_fake_dev.rs`;
it requires a sandbox with `dev/block/by-name/{lk_a,lk_b,seccfg}` and a
`bin/id` that prints `uid=0(root)`.
