# Contributing

Thanks for helping.

## Ground rules

- Keep changes small and focused.
- Match the existing style. Simple, boring, correct.
- Every LK format change needs a golden test in core/tests.
- Do not add new features that touch a device without a read only path first.

## Adding support for a new device

1. Connect the device and run the app.
2. Tap **Create support pack (PR)** (or `honor_mtk_unlocker support-pack`).
3. It dumps both LK slots plus device identity into `support-pack-<serial>/`.
4. Open a pull request and attach that folder.

A contributor can then add a fingerprint to `core/src/lk.rs` (all_recipes):

- Find the init that stores the FB unlockstate.
- Record the site offset, the original bytes, and the replacement bytes.
- Add the signature and a golden test that patches your dump and checks the
  exact output bytes.

The tool refuses unknown builds on purpose. Never remove that guard.

## Development flow

1. Fork the repository.
2. Create a branch.
3. Run `cd core && cargo test` after Rust changes.
4. Run `cd ui && flutter analyze` after UI changes.
5. Open a pull request.

## License

All contributions are licensed under GPL-3.0-or-later.
