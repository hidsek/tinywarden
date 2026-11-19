# Publishing a version

## Version numbers

`MAJOR.MINOR.PATCH` (semantic versioning). Before 1.0 the project is still a prototype and may change a lot.

- PATCH: fixes only
- MINOR: new features, or behaviour changes that need nothing from the user
- MAJOR: anything that makes people erase and re-create the vault, or re-trust the certificate (storage format, certificate form). Before 1.0 such changes bump MINOR instead, and the release notes say so in bold
- 1.0 comes when it has been used on more people's devices for a while without surprises

Development happens on `main` of this repository. A version is a tag on `main`, a GitHub release with
the merged firmware image, and the web flasher on the `gh-pages` branch.

1. `main` is clean, the CI is green, and the docs say what changed (README, docs/)
2. Tag it: `git tag -a vX.Y -m "tinywarden vX.Y"`
3. `release/build-binary.sh vX.Y` builds the image from the tag into `~/tinywarden-artifacts/vX.Y/`
   (or `$TW_ARTIFACT_DIR`) with `SHA256SUMS`, and scans it with `tools/check-leaks.sh`
4. `release/make-site.sh vX.Y` recreates the `gh-pages` branch (one commit: page, manifest, image)
5. Look at it: `git show gh-pages:index.html`, `git show vX.Y --stat`
6. Push and release:
   ```sh
   git push origin main vX.Y
   git push --force origin gh-pages
   gh release create vX.Y --title "tinywarden vX.Y" --notes "..." \
     ~/tinywarden-artifacts/vX.Y/tinywarden-vX.Y-esp32s3.bin ~/tinywarden-artifacts/vX.Y/SHA256SUMS
   ```

The flasher is at https://hidsek.github.io/tinywarden/ (Pages serves the `gh-pages` branch).

## Before committing

Run `tools/install-hooks.sh` once per clone. The pre-commit hook runs `tools/check-leaks.sh --staged`
(keys, tokens, home paths, email addresses, plus a personal list kept outside the repository, if any)
and checks that the author is the published name with a GitHub noreply address.
