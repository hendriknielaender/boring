# boring

BoringSSL bindings for Zig.

- `boringssl` is the raw `translate-c` module. It owns the BoringSSL source pin,
  CMake build, generated bindings, include paths, static link inputs, and C/C++
  runtime linkage.
- `boring` is the Zig wrapper module. It exposes Zig-shaped wrappers around the
  core BoringSSL surface while keeping internal implementation style small,
  explicit, and bounded.

## Usage

Add this package as a dependency, then import the high-level module:

```zig
const boring = @import("boring");
```

The raw FFI module is also available:

```zig
const boringssl = @import("boringssl");
```

BoringSSL's C names are preserved in the raw module, so consumers may use
declarations such as `SSL_CTX_new` and `SSL_new` when they need direct FFI.

## Build Options

By default, the package builds the pinned submodule at `deps/boringssl` with
CMake and links `ssl/libssl.a` plus `crypto/libcrypto.a`.

```sh
git submodule update --init --recursive
zig build
```

Common overrides:

```sh
zig build -Dboringssl-source-path=/path/to/boringssl
zig build -Dboringssl-include-path=/path/to/include
zig build -Dboringssl-lib-path=/path/to/boringssl/build
zig build -Dboringssl-cmake-build-type=Debug
```

`-Dboringssl-lib-path` expects the BoringSSL CMake build layout:
`ssl/libssl.a` and `crypto/libcrypto.a`.

Patch-gated BoringSSL variants are opt-in:

```sh
zig build -Dboringssl-source-path=/path/to/patched/boringssl \
  -Dboringssl-mlkem-patch=true
zig build -Dboringssl-source-path=/path/to/patched/boringssl \
  -Dboringssl-rpk-patch=true
zig build -Dboringssl-source-path=/path/to/patched/boringssl \
  -Dboringssl-underscore-wildcards-patch=true
```

The patch flags select Zig wrappers and header expectations. They do not
modify `deps/boringssl`; use a compatible patched source checkout, or pass both
`-Dboringssl-include-path` and `-Dboringssl-lib-path` for prebuilt artifacts.
The build validates the required patched headers and symbols before generating
bindings.

## Pin

The BoringSSL submodule is pinned to:

```text
7a6e828dc53ba9a56bd49915f2a0780d63af97d2
```

BoringSSL revision bumps should be treated as package releases.

To update the pin:

```sh
git submodule update --remote deps/boringssl
```

Then update `boring_ssl_revision` in `build.zig`, run the full test suite, and
commit the submodule pointer with the build-script revision.
