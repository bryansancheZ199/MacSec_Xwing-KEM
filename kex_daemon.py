#!/usr/bin/env python3
"""
Simple orchestrator for X-Wing KEM -> HKDF -> MACsec injection.
This is a PoC: do not use as-is in production without hardening.
"""

import argparse
import socket
import os
import time
import binascii
from kex_helper import (
    xwing_genkey, xwing_encaps, xwing_decaps,
    hkdf_sha3_256, key_to_hex,
    create_macsec_iface, add_tx_sa, add_rx_sa
)

# default filenames
PRIV_F = "xwing_priv.bin"
PUB_F = "xwing_pub.bin"
CIPHER_F = "enc.bin"

BUFFER_SIZE = 65536


def exchange_pub_and_kem(role: str, peer_ip: str, port: int):
    """
    Simple TCP exchange protocol (synchronous):
    - Both sides ensure pub keys exist (generate if not)
    - Responder listens and sends its pubkey when a client connects
    - Initiator connects, sends its pubkey, receives responder pubkey, runs encaps, sends ciphertext
    - Responder receives ciphertext, decaps, computes shared secret, and replies with 'OK' (or prints shared secret) -- but the shared secret should be local only
    """
    if os.path.exists(PRIV_F) and os.path.exists(PUB_F):
        priv = PRIV_F; pub = PUB_F
    else:
        priv, pub = xwing_genkey(PRIV_F, PUB_F)

    if role == "responder":
        # listen
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.listen(1)
            print("Responder: waiting for connection...")
            conn, addr = s.accept()
            with conn:
                print("Connected by", addr)
                # send our pubkey
                with open(pub, "rb") as f:
                    mypub = f.read()
                conn.sendall(len(mypub).to_bytes(4, "big") + mypub)
                # receive ciphertext length + ciphertext
                clen = int.from_bytes(conn.recv(4), "big")
                cipher = b""
                while len(cipher) < clen:
                    chunk = conn.recv(BUFFER_SIZE)
                    if not chunk:
                        break
                    cipher += chunk
                # save cipher
                with open(CIPHER_F, "wb") as cf:
                    cf.write(cipher)
                print("Ciphertext received, decapsulating...")
                shared = xwing_decaps(CIPHER_F, priv)
                print("Decapsulation complete; derived shared secret (hidden)")
                # send acknowledgement
                conn.sendall(b"OK")
                return shared

    elif role == "initiator":
        # connect to peer
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f"Initiator: connecting to {peer_ip}:{port}...")
            s.connect((peer_ip, port))
            # send our pubkey first
            with open(pub, "rb") as f:
                mypub = f.read()
            s.sendall(len(mypub).to_bytes(4, "big") + mypub)
            # receive responder pubkey
            rlen = int.from_bytes(s.recv(4), "big")
            rpub = b""
            while len(rpub) < rlen:
                rpub += s.recv(BUFFER_SIZE)
            # save peer pub
            with open("peer_pub.bin", "wb") as pf:
                pf.write(rpub)
            print("Responder pubkey received; encapsulating...")
            cipher = xwing_encaps("peer_pub.bin", CIPHER_F)
            # send ciphertext
            s.sendall(len(cipher).to_bytes(4, "big") + cipher)
            # wait for OK
            ack = s.recv(4)
            if ack.startswith(b"OK"):
                print("Responder acknowledged; initiator has no shared secret printed (peer decaps)")
            # For mutual shared secret, you can have both sides do encaps/decaps or run two-way exchange. For this PoC we use responder decapsulation.
            # If you prefer initiator to also get shared, adjust protocol to return shared secret.
            return None

    else:
        raise ValueError("Unknown role")


def derive_keys_and_configure(shared_secret: bytes, phys_if: str, peer_mac: str = None):
    # derive CAK (32 bytes) and SAK (16 bytes) for AES-GCM-128
    cak = hkdf_sha3_256(shared_secret, info=b"XWING|MACSEC|CAK", length=32)
    sak = hkdf_sha3_256(shared_secret, info=b"XWING|MACSEC|SAK", length=16)
    cak_hex = key_to_hex(cak)
    sak_hex = key_to_hex(sak)

    print("Creating macsec interface on", phys_if)
    create_macsec_iface(phys_if, "macsec0")
    print("Injecting TX SA (SA 0)")
    add_tx_sa("macsec0", 0, sak_hex, pn=1)
    if peer_mac:
        print("Injecting RX SA (SA 0) for peer MAC", peer_mac)
        add_rx_sa("macsec0", peer_mac, 1, 0, sak_hex, pn=1)
    print("Bringing interfaces up")
    os.system(f"ip link set {phys_if} up")
    os.system("ip link set macsec0 up")
    print("MACsec configuration complete")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=["initiator", "responder"], required=True)
    parser.add_argument("--if", dest="iface", default="eth0", help="Physical interface to protect")
    parser.add_argument("--peer", dest="peer_ip", default=None, help="Peer IP to connect to (initiator)")
    parser.add_argument("--listen", dest="listen_ip", default="0.0.0.0", help="IP to listen on (responder)")
    parser.add_argument("--port", type=int, default=5555)
    parser.add_argument("--peer-mac", dest="peer_mac", default=None, help="Peer MAC address (optional, for RX SA)")
    args = parser.parse_args()

    shared = exchange_pub_and_kem(args.role, args.peer_ip, args.port)
    if shared is None:
        print("No shared secret locally (initiator mode used one-way encaps). Exiting - adjust protocol if you want both sides to have it")
    else:
        derive_keys_and_configure(shared, args.iface, args.peer_mac)
