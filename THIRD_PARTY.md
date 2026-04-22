# Third Party Code

## BoringSSL

This package pins BoringSSL as a git submodule in `deps/boringssl`.

- Upstream: <https://boringssl.googlesource.com/boringssl>
- Revision: `7a6e828dc53ba9a56bd49915f2a0780d63af97d2`
- License: see `deps/boringssl/LICENSE`

BoringSSL does not provide stable API or ABI guarantees. Treat revision bumps as
package releases that may require consumer changes.
