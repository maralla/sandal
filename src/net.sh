
# Network setup
ip link set lo up 2>/dev/null
if [ -e /sys/class/net/eth0 ]; then
    ip link set eth0 up 2>/dev/null
    # Try DHCP with short timeout, then fallback to static IP
    DHCP_OK=0
    if command -v udhcpc >/dev/null 2>&1; then
        udhcpc -i eth0 -n -q -T 1 -t 2 -s /usr/share/udhcpc/default.script 2>/dev/null && DHCP_OK=1
    elif command -v dhclient >/dev/null 2>&1; then
        timeout 3 dhclient eth0 2>/dev/null && DHCP_OK=1
    fi
    # Fallback: manual IP configuration if DHCP didn't assign one
    if [ "$DHCP_OK" = "0" ]; then
        ip addr add 10.0.2.15/24 dev eth0 2>/dev/null
        ip route add default via 10.0.2.2 2>/dev/null
        echo "nameserver 10.0.2.3" > /etc/resolv.conf 2>/dev/null
    fi
fi
