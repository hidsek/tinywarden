# @noble/hashes (vendored)

Argon2id for the pages the board serves (the browser has no Argon2 of its own).

- Package: `@noble/hashes` 2.0.1 from npm (`npm pack @noble/hashes@2.0.1`), integrity
  `sha512-XlOlEbQcE9fmuXxrVTXCTlG2nlRXa9Rj3rr5Ue/+tX+nmkgbX720YHh0VR3hBF9xDvwnb8D2shVGOwNx+ulArw==`
- Files: `argon2.js` and the modules it imports (`_u64.js`, `blake2.js`, `_blake.js`, `_md.js`, `utils.js`),
  unchanged except that the `//# sourceMappingURL=` line is removed (the maps are not shipped).
- License: MIT, see `LICENSE` (Copyright (c) 2022 Paul Miller).
- Checked: Argon2id output equals OpenSSL 3.6's `openssl kdf ARGON2ID` for Bitwarden's settings
  (`test/web/test_twcrypto.mjs`).
