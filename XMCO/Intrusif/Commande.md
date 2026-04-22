## Recherche de SQLi

```bash
rg -n '(SELECT.*\$|INSERT.*\$|DELETE.*\$|UPDATE.*\$)'
```

## Recherche de RCE 

```bash
rg -n 'exec('
```

## Recherche de XSS

```bash
rg -n '(element.innerHTML|document.write\(.*\)|eval\(.*\)|echo \$_GET\[.*\])'
```

```bash
rg -n "echo .*\$" ### Bcp de faux positifs
```
