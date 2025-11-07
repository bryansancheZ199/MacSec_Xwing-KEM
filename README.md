# MacSec
Instalation and implementation od MACSec in 2 raspberry's pi 5

Hardware configuration:
- 2 raspberry's
- 4 patchcords
- 1 non managable switch
- 1 computer
- internet comunication

Operative system OpenWRT:
- https://firmware-selector.openwrt.org/
- search for raspberry pi 5
- Download image Factory (EXT4)
- burn the image into the micro sd card with the software https://rufus.ie/en/


Quick start (PoC)

1. Place a compiled xwing_cli binary in the same folder as the scripts (or in your PATH). The CLI must implement the following minimal interface:

-- xwing_cli genkey --priv <privfile> --pub <pubfile> — produce private/public key files (raw bytes or hex).

-- xwing_cli encaps --peer <peer_pubfile> --out <cipherfile> — produce ciphertext file (and optionally print shared secret in hex to stdout or to a file).

-- xwing_cli decaps --cipher <cipherfile> --priv <privfile> — print the shared secret in hex to stdout.

2. Run the script on both peers. Decide which device is initiator (it will encapsulate using the responder's public key). Example invocation:

  On Responder (device B):
```shell
sudo python3 kex_daemon.py --role responder --if eth0 --listen 0.0.0.0 --port 5555
```
  On Initiator (device A):
```shell
sudo python3 kex_daemon.py --role initiator --if eth0 --peer 192.168.1.2 --port 5555
```
The script will:

- generate an X-Wing keypair (or reuse existing files xwing_priv.bin/xwing_pub.bin if present),

- exchange public keys and encaps/decaps over TCP,

- derive CAK and a SAK from the shared secret using HKDF(SHA3-256),

- configure macsec0 over the given physical interface (eth0 by default) and inject TX/RX SAs using ip macsec.

3. Verify MACsec

- Run ip -d link show macsec0 to inspect MACsec state and counters.

- Run packet capture on the physical interface (tcpdump -i eth0 -w before.pcap) and on macsec0 to confirm frames are encrypted on the wire.

Some Iperf3 tests has been done with the macsec configuration and with out it, the files of the results are attached in the files of this repository.
