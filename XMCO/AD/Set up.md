Récupérer les réseaux de la kali sur son container:

Kali:
```bash
scp -J echo /opt/tools/ligolo-ng/agent kali@<IP_TP>:/tmp/agent
ssh -J echo kali@<IP_TP> -R 11601:localhost:11601

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
