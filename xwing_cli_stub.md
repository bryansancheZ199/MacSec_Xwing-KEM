# xwing_cli stub — how to obtain / build

This file explains how to obtain an `xwing_cli` binary for the PoC.

- **Option 1 (recommended for PoC)**: use an existing X-Wing implementation and compile a tiny CLI wrapper. Example project names: `xwing-kem` or `xwing` (search upstream implementations). Create a small CLI that calls the KEM functions and prints the shared secret hex when decaps is called.

- **Option 2 (cross-compile)**: cross-compile a Linux binary for the Raspberry Pi 5 (aarch64) on a workstation and copy it to the devices. Use a standard cross toolchain or Docker cross-compilation environment.

- **Option 3 (use prebuilt)**: if you find a prebuilt aarch64 binary that matches your kernel/GLIBC, copy it onto the devices. This is less recommended for security reasons.

**CLI behavior expected by the Python scripts**
- `genkey --priv <privfile> --pub <pubfile>`: writes private and public key files (raw bytes)
- `encaps --peer <peer_pubfile> --out <cipherfile>`: writes ciphertext file, (optionally prints shared secret to stdout)
- `decaps --cipher <cipherfile> --priv <privfile>`: prints the shared secret in hex to stdout


### Minimal Rust CLI (sketch)

You can implement a minimal CLI in Rust using an existing X-Wing crate or embedding a C implementation. The CLI should expose three subcommands above. Use `structopt` or `clap` to parse subcommands and `std::fs::write` to dump files.

### Cross-compiling for Raspberry Pi 5 (aarch64)

1. Install `aarch64-unknown-linux-gnu` toolchain or use Docker with an aarch64 SDK.
2. Build with `cargo build --release --target aarch64-unknown-linux-gnu` (for Rust).
3. Copy the binary to the Pi and mark it executable `chmod +x xwing_cli`.


### Security note
- Make sure the CLI doesn't inadvertently print private keys. For decapsulation it may optionally print the shared secret (useful for debugging) — remove that for production.

