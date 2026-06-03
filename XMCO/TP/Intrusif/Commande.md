1## Recherche de SQLi

```bash
rg -n '(SELECT.*\$|INSERT.*\$|DELETE.*\$|UPDATE.*\$)'
```

```shell
rg -U -n '(SELECT[\s\S]*?\$[\S]*?\))' ### Bcp de faux positifs  
```

```shell
rg -U -n '(INSERT[\s\S]*?\$[\S]*?\))' ### Bcp de faux positifs  
```

```shell
rg -U -n '(DELETE[\s\S]*?\$[\S]*?\))' ### Bcp de faux positifs  
```

```shell
rg -U -n '(UPDATE[\s\S]*?\$[\S]*?\))' ### Bcp de faux positifs  
```

## Recherche de RCE 

```bash
rg -n 'exec\(|shell_exec\(|system\(|popen\('
```

### FIle Upload

```bash
rg -n 'move_uploaded_file\(|file_put_contents\(|fwrite\(|fputs\(|include\(|require\(|include_once\(|require_once\('
```

## Recherche de XSS

```bash
rg -n '(element.innerHTML|document.write\(.*\)|eval\(.*\)|echo \$_GET\[.*\])'
```

```bash
rg -n "echo .*\$" ### Bcp de faux positifs
```
