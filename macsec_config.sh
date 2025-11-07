#!/bin/sh
# Run as root
PHY_IF=eth0
MACSEC_IF=macsec0
SAHEX=<sak-hex-here>

ip link add link $PHY_IF $MACSEC_IF type macsec port 1 encrypt on || true
ip macsec add $MACSEC_IF tx sa 0 pn 1 on key 01 $SAHEX
# Replace <peer-mac> with the peer's MAC address to add RX SA
# ip macsec add $MACSEC_IF rx soc eth0 addr <peer-mac> 1 sa 0 pn 1 key 01 $SAHEX
ip link set $PHY_IF up
ip link set $MACSEC_IF up
