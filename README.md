# xwing-macsec-poc

Proof-of-concept repository to establish a post-quantum–resistant point-to-point MACsec link between two openWrt devices (example: Raspberry Pi 5 running) using an X‑Wing KEM for key exchange and a Python orchestrator that injects MACsec keys.

## Installed apps on openWrt devices
```sh
opkg update
opkg install rsync
opkg install kmod-macsec
opkg install kmod-macsec ip-full
opkg install python3 python3-pip
```

## Quick start 

1. Clone the repository in a device and copy the following files into the devices with clean version of openWrt (works well using rsync) exmaple:
```sh
   rsync -avz --progress \
    xwing_cli/target/aarch64-unknown-linux-gnu/release/xwing_cli \
    kex_daemon.py \
    kex_helper.py \
    macsec_config.sh \
    root@<Ip_of_device>:/tmp/macsec-xwing/
```

2. Run the script on both peers. Decide which device is `initiator` (it will encapsulate using the responder's public key). Example invocation:

   On Responder (device B):
   ```sh
   python3 kex_daemon.py --role responder --if eth0 --listen 0.0.0.0 --port 5555
   ```

   On Initiator (device A):
   ```sh
   python3 kex_daemon.py --role initiator --if eth0 --peer <Ip_of_peer> --port 5555
   ```

   The script will:
   - generate an X-Wing keypair,
   - exchange public keys and encaps/decaps over TCP,
   - derive CAK and a SAK from the shared secret using HKDF(SHA3-256),
   - configure `macsec0` over the given physical interface (`eth0` by default) and inject TX/RX SAs using `ip macsec`.

3. Verify MACsec
   - Run `ip -d link show macsec0` to inspect MACsec state and counters.
   - Run packet capture on the physical interface (`tcpdump -i eth0 -w before.pcap`) and on `macsec0` to confirm frames are encrypted on the wire.

## Files included
- `Instructions_and_commands.txt` — simple running commands
- `kex_daemon.py` — main Python orchestrator
- `kex_helper.py` — helpers (KEM wrappers, HKDF, macsec calls)
- `macsec_config.sh` — example shell fragment showing ip commands
- `xwing_cli` — Rust implementation for xwing KEM algorithm
- `TESTING.md` — Suggested tests after the system runs

    

