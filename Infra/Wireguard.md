## 1. Key Generation (Server & Client)

Generate server keys:
```bash
wg genkey | tee privatekey_server | wg pubkey > publickey_server
```

Generate client keys:
```bash
wg genkey | tee privatekey_client | wg pubkey > publickey_client
```

---

## 2. Server Configuration (`/etc/wireguard/wg0.conf`)

```ini
[Interface]
PrivateKey = <server_private_key>
Address = 10.0.0.1/24
ListenPort = 51820

PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = <client_public_key>
AllowedIPs = 10.0.0.2/32
```

**PostUp** (executed when the `wg0` interface starts):  
1. `iptables -A FORWARD -i wg0 -j ACCEPT` → Allow forwarding of **incoming packets** from `wg0`.  
2. `iptables -A FORWARD -o wg0 -j ACCEPT` → Allow forwarding of **outgoing packets** to `wg0`.  
3. `iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE` → Enable **NAT (masquerading)** so VPN clients use the server’s public IP on interface `eth0` to access the internet.  

**PostDown** (executed when the `wg0` interface stops):  
Removes (`-D`) the same firewall rules to clean up the configuration.

---

## 3. Client Configuration (`wg0-client.conf`)

```ini
[Interface]
PrivateKey = <client_private_key>
Address = 10.0.0.2/24

[Peer]
PublicKey = <server_public_key>
Endpoint = <server_public_ip>:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

---

## 4. Starting & Stopping WireGuard

Start server:
```bash
sudo wg-quick up wg0
```

Stop server:
```bash
sudo wg-quick down wg0
```

Restart server:
```bash
sudo systemctl restart wg-quick@wg0
```

---

## 5. Enable IP Forwarding (Permanent)

Edit sysctl config:
```bash
sudo nano /etc/sysctl.conf
```
Uncomment:
```
net.ipv4.ip_forward=1
```

Apply changes without reboot:
```bash
sudo sysctl -p
```

---

## 6. Importing WireGuard Config into GNOME

Import:
```bash
nmcli connection import type wireguard file /etc/wireguard/wg0.conf
```

List connections:
```bash
nmcli connection show
```

Delete connection:
```bash
nmcli connection delete wg0
```

---

## 7. Concept: Public/Private Keys & Session Keys

Example:
```
Client Private: c = 5
Server Private: s = 7

Client Public: C = 5G
Server Public: S = 7G

Session key = c × S = 5 × 7G = 35G
              s × C = 7 × 5G = 35G
```

---

## 8. Packet Flow

```
Client                    Internet                    VPN Server
+------------+            +---------+                +------------+
| IP Packet  | --Encrypt--> VPN Packet (UDP) --Decrypt--> IP Packet |
| (SSH,HTTP) | --Encap--> --Transmit--> --Decap--> --Route-->       |
+------------+            +---------+                +------------+
```

---

## 9. GPG Key Generation

Generate GPG key:
```bash
gpg --full-gen-key
```
