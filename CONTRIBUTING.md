# Contributing

Thanks for helping.

## Ground rules

- Keep changes small and focused.
- Match the existing style. Simple, boring, correct.
- Every LK format change needs a golden test in core/tests.
- Do not add new features that touch a device without a read only path first.

## AI assistance

AI assistance is allowed and welcome. The author is responsible for verifying
the result: run the tests, run the offline patch check, and confirm the bytes
yourself. AI-generated code that fails verification is rejected like any other
code. Failing to verify a device-affecting change is a serious issue.

## Adding support for a new device

1. Connect the device and run the app.
2. Tap **Create support pack (PR)** (or `honor_mtk_unlocker support-pack`).
3. It dumps both LK slots plus device identity into `support-pack-<serial>/`.
4. Open a pull request and attach that folder.

Attach `lk_a.bin` and `lk_b.bin` from the support pack to the PR. GitHub
accepts binary attachments up to 25 MB, so the LK dumps fit directly. Do not
attach seccfg, oeminfo, or any other partition dumps.

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
