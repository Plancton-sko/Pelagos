#!/bin/bash
set -e

echo "[+] Configuring Tor..."
mkdir -p /var/lib/tor
chmod 700 /var/lib/tor

cat << EOF > /etc/tor/torrc
SocksPort 127.0.0.1:9050
ControlPort 127.0.0.1:9051
CookieAuthentication 0
DataDirectory /var/lib/tor
EOF

echo "[+] Starting Tor background service..."
tor -f /etc/tor/torrc &

echo "[+] Waiting for Tor SOCKS5 and ControlPort..."
for i in {1..30}; do
    if nc -z 127.0.0.1 9050 && nc -z 127.0.0.1 9051; then
        echo "[+] Tor daemon is running!"
        break
    fi
    sleep 1
done

echo "[+] Launching Palagos Zero-Trust Relay Server..."
exec /app/palagos-server -addr 0.0.0.0:8080 -transport onion -socks 127.0.0.1:9050 -tor-control 127.0.0.1:9051
