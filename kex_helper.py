# kex_helper.py
# Helpers: run xwing_cli, KDF, macsec command wrappers

import subprocess
import binascii
import os
from pathlib import Path
from hashlib import sha3_256
from typing import Tuple

# Find xwing_cli in the same directory as this script
SCRIPT_DIR = Path(__file__).parent.absolute()
XWING_CLI = SCRIPT_DIR / "xwing_cli"

# Simple HKDF (extract->expand) using SHA3-256
def hkdf_sha3_256_extract(salt: bytes, ikm: bytes) -> bytes:
    if salt is None or len(salt) == 0:
        salt = b"\x00" * 32
    h = sha3_256()
    h.update(salt + ikm)
    return h.digest()

def hkdf_sha3_256_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        h = sha3_256()
        h.update(t + info + bytes([counter]))
        t = h.digest()
        out += t
        counter += 1
    return out[:length]

def hkdf_sha3_256(ikm: bytes, info: bytes = b"", salt: bytes = b"", length: int = 32) -> bytes:
    prk = hkdf_sha3_256_extract(salt, ikm)
    return hkdf_sha3_256_expand(prk, info, length)

# xwing_cli wrappers - finds xwing_cli in the same directory as this script
def xwing_genkey(priv_path: str = "xwing_priv.bin", pub_path: str = "xwing_pub.bin") -> Tuple[str,str]:
    cmd = [str(XWING_CLI), "gen-key", "--priv-out", priv_path, "--pub-out", pub_path]
    subprocess.run(cmd, check=True)
    return priv_path, pub_path

def xwing_encaps(peer_pub_path: str, out_cipher: str = "enc.bin") -> bytes:
    cmd = [str(XWING_CLI), "encapsulate", "--peer", peer_pub_path, "--out", out_cipher]
    # CLI outputs shared secret hex to stdout
    result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    cipher_data = open(out_cipher, "rb").read()
    return cipher_data

def xwing_encaps_with_ss(peer_pub_path: str, out_cipher: str = "enc.bin") -> Tuple[bytes, bytes]:
    """Encapsulate and return both ciphertext and shared secret"""
    cmd = [str(XWING_CLI), "encapsulate", "--peer", peer_pub_path, "--out", out_cipher]
    result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    cipher_data = open(out_cipher, "rb").read()
    # Extract shared secret from stdout (hex encoded)
    hex_ss = result.stdout.strip().decode()
    shared_secret = binascii.unhexlify(hex_ss)
    return cipher_data, shared_secret

def xwing_decaps(cipher_path: str, priv_path: str) -> bytes:
    cmd = [str(XWING_CLI), "decapsulate", "--cipher", cipher_path, "--priv-key", priv_path]
    out = subprocess.run(cmd, check=True, stdout=subprocess.PIPE)
    # expect stdout to contain hex of shared secret
    hexshared = out.stdout.strip().decode()
    return binascii.unhexlify(hexshared)

# convert binary key to macsec hex string (no 0x prefix)
def key_to_hex(key: bytes) -> str:
    return binascii.hexlify(key).decode()

# macsec injector — executes ip macsec commands; expects to run as root
import shlex

def run_cmd(cmd_list):
    subprocess.run(cmd_list, check=True)

def create_macsec_iface(phys_if: str, macsec_if: str = "macsec0"):
    # idempotent style: try to delete existing macsec first (ignore errors)
    try:
        run_cmd(["ip", "link", "del", macsec_if])
    except Exception:
        pass
    try:
        run_cmd(["ip", "link", "add", "link", phys_if, macsec_if, "type", "macsec", "port", "1", "encrypt", "on"])
    except subprocess.CalledProcessError as e:
        error_msg = str(e)
        if "Not supported" in error_msg or "RTNETLINK" in error_msg or "can't find device" in error_msg:
            print(f"ERROR: MACsec is not supported on this system")
            print(f"")
            print(f"To enable MACsec on OpenWrt, you need:")
            print(f"  1. Install MACsec kernel module: opkg install kmod-macsec")
            print(f"  2. Install full iproute2 (not BusyBox): opkg install ip-full")
            print(f"  3. Or compile OpenWrt with MACsec support enabled in kernel config")
            print(f"")
            print(f"Note: BusyBox's 'ip' command doesn't support MACsec subcommands.")
            print(f"You need the full iproute2 package.")
            raise RuntimeError("MACsec not supported - install kmod-macsec and ip-full")
        else:
            raise

def add_tx_sa(macsec_if: str, sa_id: int, key_hex: str, pn: int = 1):
    # key id '01' is used as an example; some setups use a CKN/CAK and MKA - here we inject SA directly
    keyid = "01"
    try:
        run_cmd(["ip", "macsec", "add", macsec_if, "tx", "sa", str(sa_id), "pn", str(pn), "on", "key", keyid, key_hex])
    except subprocess.CalledProcessError as e:
        error_msg = str(e)
        if "Usage:" in error_msg or "BusyBox" in error_msg:
            print(f"ERROR: BusyBox 'ip' command doesn't support MACsec")
            print(f"Install full iproute2: opkg install ip-full")
            raise RuntimeError("MACsec commands not available - install ip-full")
        else:
            raise

def add_rx_sa(macsec_if: str, peer_mac: str, port: int, sa_id: int, key_hex: str, pn: int = 1):
    keyid = "01"
    try:
        run_cmd(["ip", "macsec", "add", macsec_if, "rx", "soc", "eth0", "addr", peer_mac, str(port), "sa", str(sa_id), "pn", str(pn), "key", keyid, key_hex])
    except subprocess.CalledProcessError as e:
        error_msg = str(e)
        if "Usage:" in error_msg or "BusyBox" in error_msg:
            print(f"ERROR: BusyBox 'ip' command doesn't support MACsec")
            print(f"Install full iproute2: opkg install ip-full")
            raise RuntimeError("MACsec commands not available - install ip-full")
        else:
            raise
