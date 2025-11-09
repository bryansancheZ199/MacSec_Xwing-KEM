# MACsec X-Wing KEM Testing Guide

## 1. Verify MACsec Connection is Active

### Check MACsec Interface Status

**On both devices:**
```bash
# Check if MACsec interface exists and is up
ip link show macsec0

# Detailed MACsec information
ip -d link show macsec0

# Check MACsec statistics
ip -s link show macsec0
```

**Expected output should show:**
- Interface state: `UP`
- Type: `macsec`
- Encryption: `on`
- TX/RX SA counters

### Check MACsec Security Associations (SAs)

**On both devices:**
```bash
# List TX SAs
ip macsec show macsec0

# Detailed SA information
ip -d macsec show macsec0
```

**Expected output:**
- TX SA 0 should be active
- RX SA 0 should be active (if peer MAC was specified)
- Packet numbers (PN) should be incrementing

## 2. Test Connectivity Through MACsec

### Basic Connectivity Test

**On Raspberry Pi 1:**
```bash
# Ping through MACsec interface
ping -I macsec0 192.168.10.2

# Or if you configured IP on macsec0:
ping 192.168.10.2
```

**On Raspberry Pi 2:**
```bash
ping -I macsec0 192.168.10.1
```

### Verify Traffic is Encrypted

**On both devices, capture packets:**

**Terminal 1 - Capture on physical interface (should show encrypted frames):**
```bash
tcpdump -i eth0 -w /tmp/physical_interface.pcap -c 100
```

**Terminal 2 - Capture on MACsec interface (should show plaintext):**
```bash
tcpdump -i macsec0 -w /tmp/macsec_interface.pcap -c 100
```

**Then compare the captures:**
```bash
# Physical interface should show MACsec-encrypted frames (larger, encrypted)
tcpdump -r /tmp/physical_interface.pcap -n

# MACsec interface should show plaintext frames
tcpdump -r /tmp/macsec_interface.pcap -n
```

**Key indicators:**
- Physical interface: Frames have MACsec headers, larger size, encrypted payload
- MACsec interface: Normal Ethernet frames, readable payload

## 3. Performance Testing

### Throughput Test

**Install iperf3 on both devices:**
```bash
opkg update
opkg install iperf3
```

**On Raspberry Pi 1 (Server):**
```bash
iperf3 -s -p 5201
```

**On Raspberry Pi 2 (Client):**
```bash
# Test TCP throughput
iperf3 -c 192.168.10.1 -p 5201 -t 60 -i 1

# Test UDP throughput
iperf3 -c 192.168.10.1 -p 5201 -u -b 1000M -t 60 -i 1
```

**Test through MACsec interface:**
```bash
# On Pi 1
iperf3 -s -p 5201 -B macsec0

# On Pi 2
iperf3 -c 192.168.10.1 -p 5201 -B macsec0 -t 60 -i 1
```

### Latency Test

**On Raspberry Pi 1:**
```bash
# BusyBox ping doesn't support decimal intervals, use integer seconds
ping -I macsec0 -c 1000 -i 1 192.168.10.2 | tail -1

# For faster testing (minimum 1 second interval on BusyBox)
ping -I macsec0 -c 100 192.168.10.2 | tail -1
```

**Calculate statistics:**
```bash
ping -I macsec0 -c 1000 192.168.10.2 | grep "min/avg/max"

# Or get detailed stats
ping -I macsec0 -c 1000 192.168.10.2 | tail -1
```

### CPU Usage During Transfer

**On both devices, monitor CPU while running iperf3:**
```bash
# In another terminal
top -d 1
# or
htop
```

## 4. Security Testing

### Verify Encryption is Active

**Check that frames on wire are encrypted:**

**On Raspberry Pi 1:**
```bash
# Capture packets on physical interface
tcpdump -i eth0 -X -c 10 'ether proto 0x88e5'
```

**Expected:**
- MACsec protocol (0x88e5) frames
- Encrypted payload (not readable)
- MACsec headers visible

### Verify Key Exchange Security

**Check that keys are not exposed:**
```bash
# Keys should be in binary files, not readable
file xwing_priv.bin xwing_pub.bin
hexdump -C xwing_priv.bin | head -5
```

**Verify shared secret derivation:**
- Both devices should derive the same CAK and SAK from the shared secret
- Keys should be different for each session (if you regenerate)

### Test MACsec Protection

**Try to inject unencrypted frames:**
```bash
# This should fail or be rejected by MACsec
# Attempt to send raw frame (requires special tools)
```

**Monitor MACsec error counters:**
```bash
ip -s link show macsec0
# Look for:
# - Invalid packets
# - Authentication failures
# - Decryption errors
```

### Verify Forward Secrecy

**Test that old keys don't work:**
1. Run key exchange once
2. Note the SAK
3. Run key exchange again (new keys)
4. Verify old SAK doesn't decrypt new traffic

## 5. Advanced Monitoring

### Real-time MACsec Statistics

**Watch MACsec counters:**
```bash
watch -n 1 'ip -s link show macsec0'
```

**Monitor SA packet numbers:**
```bash
watch -n 1 'ip macsec show macsec0'
```

### Check MACsec Configuration

**Detailed interface info:**
```bash
ip -d link show macsec0 | grep -A 20 macsec
```

**Check encryption settings:**
```bash
ip -d link show macsec0 | grep -i encrypt
```

## 6. Benchmarking Script

Create a simple benchmark script:

```bash
#!/bin/sh
# benchmark_macsec.sh

echo "=== MACsec Performance Benchmark ==="
echo ""

echo "1. Latency Test (1000 packets):"
ping -I macsec0 -c 1000 -q 192.168.10.2 | tail -1

echo ""
echo "2. Throughput Test (30 seconds):"
iperf3 -c 192.168.10.2 -p 5201 -t 30 -i 1 | tail -3

echo ""
echo "3. MACsec Statistics:"
ip -s link show macsec0 | grep -E "RX|TX|packets|bytes"

echo ""
echo "4. SA Status:"
ip macsec show macsec0
```

## 7. Security Verification Checklist

- [ ] Physical interface shows encrypted frames (tcpdump on eth0)
- [ ] MACsec interface shows plaintext frames (tcpdump on macsec0)
- [ ] MACsec protocol identifier (0x88e5) present on wire
- [ ] Packet counters incrementing correctly
- [ ] No authentication failures in statistics
- [ ] Keys are stored securely (file permissions 600)
- [ ] Shared secret is not logged or exposed
- [ ] Each session uses different keys

## 8. Troubleshooting

### If MACsec interface is down:
```bash
ip link set macsec0 up
```

### If no traffic:
```bash
# Check routing
ip route show

# Check ARP
ip neigh show

# Verify IP configuration on macsec0
ip addr show macsec0
```

### If performance is poor:
- Check CPU usage
- Verify hardware offloading (if available)
- Check for packet drops: `ip -s link show macsec0`
- Monitor system resources: `top`, `free`, `iostat`

root@OpenWrt:~# ping -I macsec0 -c 1000 -i 0.01 192.168.10.2 | tail -1
ping: invalid number '0.01'
