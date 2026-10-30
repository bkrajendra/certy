<div align="center">

# certy — Custom Root CA Importer

Professional interactive CLI tool to import a custom root CA certificate into the **system trust store** on Windows, Linux, and macOS.

[![GitHub release](https://img.shields.io/github/v/release/bkrajendra/certy?include_prereleases&sort=semver&label=release)](https://github.com/bkrajendra/certy/releases)
[![CI / Release](https://img.shields.io/github/actions/workflow/status/bkrajendra/certy/release.yml?branch=main&label=CI%2FRelease)](https://github.com/bkrajendra/certy/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform: Windows \| Linux \| macOS](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/bkrajendra/certy/releases)

</div>

---

## Quick start

### Run from source

```bash
# Build
cargo build --release

# Run interactively (uses ca-cert.pem next to the binary)
./target/release/certy

# Skip confirmation prompt
./target/release/certy --yes

# Specify a different certificate file
./target/release/certy --cert /path/to/ca-cert.pem
```

---

## Usage

```text
certy [OPTIONS]

Options:
  -c, --cert <FILE>    Path to the CA certificate PEM file
                       (default: ca-cert.pem next to the binary)
  -y, --yes            Skip the confirmation prompt and proceed automatically
      --force          Import even if the file does not look like a PEM certificate
  -v, --verbose        Enable verbose output
  -V, --version        Print version
  -h, --help           Print help
```

---

## How it works

| Platform | Trust store | Tool used | Required privileges |
|----------|-------------|-----------|---------------------|
| Windows | Local-machine Trusted Root Certification Authorities | `certutil.exe -addstore -f ROOT` | Administrator |
| macOS | System keychain (`trustRoot`) | `security add-trusted-cert` | `sudo` |
| Linux | Distro CA anchors + trust update | `update-ca-certificates` / `update-ca-trust extract` / `trust extract-compat` | `root` |

* PEM certificates are converted to DER on Windows (certutil requirement); Linux and macOS consume PEM directly.
* Linux distros are detected from `/etc/os-release` so the correct anchor directory and update command are used automatically.
* The certificate file is located next to the running binary unless `--cert` is specified.

---

## Build multi-OS binaries

You can build binaries for all supported platforms from a single machine (macOS shown here) using `rustup` cross-compilation targets.

### Prerequisites

Install the linkers for the foreign targets:

```bash
# Windows (MinGW) linker
brew install mingw-w64

# Linux static linker (musl) — easiest way to cross-compile Linux from macOS
brew install FiloSottile/musl-cross/musl-cross
```

### Rust targets

```bash
rustup target add \
  aarch64-apple-darwin \
  x86_64-apple-darwin \
  x86_64-pc-windows-gnu \
  x86_64-unknown-linux-musl
```

### Cargo linker config

Create `.cargo/config.toml` in the project root so Cargo knows which linker to use for each target:

```toml
[target.aarch64-apple-darwin]
linker = "clang"
ar = "llvm-ar"

[target.x86_64-apple-darwin]
linker = "clang"
ar = "llvm-ar"

[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"
ar = "x86_64-w64-mingw32-ar"

[target.x86_64-unknown-linux-musl]
linker = "x86_64-linux-musl-gcc"
ar = "x86_64-linux-musl-ar"
```

### Build commands

Run these from the project root:

```bash
# macOS Apple Silicon (M1 / M2 / M3)
cargo build --release --target aarch64-apple-darwin

# macOS Intel
cargo build --release --target x86_64-apple-darwin

# Windows 64-bit (MinGW)
cargo build --release --target x86_64-pc-windows-gnu

# Linux 64-bit (static musl, runs on most distros)
cargo build --release --target x86_64-unknown-linux-musl
```

Or build everything at once:

```bash
cargo build --release --target aarch64-apple-darwin \
            --target x86_64-apple-darwin \
            --target x86_64-pc-windows-gnu \
            --target x86_64-unknown-linux-musl
```

### Output locations

| Target | Binary path | Extension |
|--------|-------------|-----------|
| macOS Apple Silicon | `target/aarch64-apple-darwin/release/certy` | none |
| macOS Intel | `target/x86_64-apple-darwin/release/certy` | none |
| Windows 64-bit | `target/x86_64-pc-windows-gnu/release/certy.exe` | `.exe` |
| Linux 64-bit | `target/x86_64-unknown-linux-musl/release/certy` | none |

Copy `ca-cert.pem` next to each binary you distribute.

### Distributable archives

```bash
# macOS
tar -czf certy-macos-arm64.tar.gz -C target/aarch64-apple-darwin/release certy
tar -czf certy-macos-x64.tar.gz -C target/x86_64-apple-darwin/release certy

# Windows
zip certy-win64.zip -j target/x86_64-pc-windows-gnu/release/certy.exe

# Linux
tar -czf certy-linux-x64.tar.gz -C target/x86_64-unknown-linux-musl/release certy
```

---

## Example output

```
╔═══════════════════════════════════════════════════════╗
║          Custom Root CA Importer                      ║
║          System trust store installer                 ║
║          Windows · Linux · macOS                      ║
╚═══════════════════════════════════════════════════════╝

[INFO] Operating system: Apple macOS
[OK  ] Found: ./ca-cert.pem  (1350 bytes)
[INFO] Format: PEM
[▶] Checking privileges…
[OK  ] Running with elevated privileges (administrator / root).
[?] Import ./ca-cert.pem into the system trust store? [y/N]: y
[▶] Importing certificate into the trust store…
[OK  ] Certificate imported into the system trust store.
[▶] Verifying installation…
[OK  ] Verification passed: certificate is registered in the trust store.

Notes:
  • Chrome and Firefox maintain their own certificate stores and will not pick up this change.
  • Restart affected applications (or reboot on Windows) for the change to take full effect.
  • Remove the certificate later via the OS certificate manager or trust-store command.

[OK] Done.
```

---

## Notes

* **Privileges:** Windows requires Administrator; macOS and Linux require `root` / `sudo` to modify the system trust store.
* **Browsers:** Chrome and Firefox maintain their own certificate stores and will not pick up system-level changes.
* **Activation:** Restart affected applications after installation. On Windows, a reboot may be required for the change to take full effect.
* **Removal:** Remove the certificate later via the OS certificate manager (Certlm.msc on Windows, Keychain Access on macOS, or the distro's trust-store command on Linux).
