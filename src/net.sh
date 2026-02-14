
# Network setup
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ip link set lo up 2>/dev/null
if [ -e /sys/class/net/eth0 ]; then
    ip link set eth0 up 2>/dev/null
    ip addr add 10.0.2.15/24 dev eth0 2>/dev/null
    ip route add default via 10.0.2.2 2>/dev/null
    echo "nameserver 10.0.2.3" > /etc/resolv.conf 2>/dev/null
fi
