# xwing-macsec-poc

Proof-of-concept repository to establish a post-quantum–resistant point-to-point MACsec link between two devices (example: Raspberry Pi 5 running OpenWrt/Linux) using an X‑Wing KEM for key exchange and a Python orchestrator that injects MACsec keys.

## Quick start (PoC)

1. Place a compiled `xwing_cli` binary in the same folder as the scripts (or in your PATH). The CLI must implement the following minimal interface:
   - `xwing_cli genkey --priv <privfile> --pub <pubfile>` — produce private/public key files (raw bytes or hex).
   - `xwing_cli encaps --peer <peer_pubfile> --out <cipherfile>` — produce ciphertext file (and optionally print shared secret in hex to stdout or to a file).
   - `xwing_cli decaps --cipher <cipherfile> --priv <privfile>` — print the shared secret in hex to stdout.

2. Run the script on both peers. Decide which device is `initiator` (it will encapsulate using the responder's public key). Example invocation:

   On Responder (device B):
   ```sh
   sudo python3 kex_daemon.py --role responder --if eth0 --listen 0.0.0.0 --port 5555
   ```

   On Initiator (device A):
   ```sh
   sudo python3 kex_daemon.py --role initiator --if eth0 --peer 192.168.1.2 --port 5555
   ```

   The script will:
   - generate an X-Wing keypair (or reuse existing files `xwing_priv.bin`/`xwing_pub.bin` if present),
   - exchange public keys and encaps/decaps over TCP,
   - derive CAK and a SAK from the shared secret using HKDF(SHA3-256),
   - configure `macsec0` over the given physical interface (`eth0` by default) and inject TX/RX SAs using `ip macsec`.

3. Verify MACsec
   - Run `ip -d link show macsec0` to inspect MACsec state and counters.
   - Run packet capture on the physical interface (`tcpdump -i eth0 -w before.pcap`) and on `macsec0` to confirm frames are encrypted on the wire.

## Files included
- `kex_daemon.py` — main Python orchestrator
- `kex_helper.py` — helpers (KEM wrappers, HKDF, macsec calls)
- `macsec_config.sh` — example shell fragment showing ip commands
- `xwing_cli_stub.md` — instructions to obtain/compile xwing_cli
- `systemd/xwing-kex.service` — example systemd unit
- `LICENSE` — MIT license template

## Security considerations
- Do not log shared secrets or expose them via stdout in production. For PoC the wrapper may print hex for debugging; remove that in hardened deployments.
- Keep private keys and generated CAK/SAK files accessible only to root (file perms 600).
- Consider using secure storage (kernel keyring, TPM, or hardware secure element) for long-term private key protection.
- This PoC directly injects SAs with `ip macsec` for simplicity. A recommended production deployment uses MKA (MACsec Key Agreement) or an authenticated key distribution mechanism.


## Next steps
1. Add a small Rust `xwing_cli` implementation + build instructions and a cross-compile guide for Raspberry Pi 5 / OpenWrt.
2. Harden the Python script (drop privileges, avoid writing keys to disk, integrate kernel keyring).
3. Make the exchange mutually authenticated (mutual encapsulation) so both peers derive the same shared secret locally.
4. Add unit tests and a script to verify that frames on the wire are encrypted.


---

MIT Licensed. Replace copyright owner as needed.

