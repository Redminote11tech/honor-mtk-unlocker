# Contributing

Thanks for helping.

## Ground rules

- Keep changes small and focused.
- Match the existing style. Simple, boring, correct.
- Every LK or seccfg format change needs a golden test in core/tests.
- Do not add new features that touch a device without a read only path first.

## Development flow

1. Fork the repository.
2. Create a branch.
3. Run `cd core && cargo test` after Rust changes.
4. Run `cd ui && flutter analyze` after UI changes.
5. Open a pull request.

## Firmware fingerprints

To support a new LK build:

1. Dump the original lk_a partition.
2. Find the init that stores the FB unlockstate.
3. Add the signature to core/src/lk.rs, all_recipes.
4. Add a golden test that patches your dump and checks the exact bytes.

The tool refuses unknown builds on purpose. Never remove that guard.

## License

All contributions are licensed under GPL-3.0-or-later.
