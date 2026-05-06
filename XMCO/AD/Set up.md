Récupérer les réseaux de la kali sur son container:

Kali:
```bash
scp /opt/tools/ligolo-ng/agent kali@15.188.194.116:/tmp/agent
ssh kali@15.188.194.116 -R 11601:localhost:11601

./agent -connect 127.0.0.1:11601 -accept-fingerprint D5AEA6D8795181B310DBFBA25D0CCB86FD8409793CFC4F8C5452BDF3068B89DB
```

Container:
```bash
exegol start pentest-xmco free -p 6666:6666

/opt/tools/ligolo-ng/proxy -selfcert
certificate_fingerprint

ifcreate --name ligolo
route_add --name ligolo --route $IP/$MASK
tunnel_start --tun ligolo

## Pour forward un port Web sur mon host local:
socat TCP-LISTEN:6666,fork TCP:<ip machine>:80

```

```
Port forward un port exegol vers ma machine:
socat TCP-LISTEN:9999,fork,reuseaddr TCP:10.2.62.235:80
```
