When a process runs on Linux, it has **three main User IDs (UIDs)** that define its privileges and identity.

---

## 1 Types of UIDs

| Name                       | Meaning                                                                                      | Example                                            |
| -------------------------- | -------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| **RUID** (*Real UID*)      | The UID of the user who **launched** the process. Identifies the process owner.              | `1000` (user) if you run the program as your user. |
| **EUID** (*Effective UID*) | The UID used **for permission checks** during execution. Determines what the process can do. | `0` (root) if you run a SUID root binary.          |
| **SUID** (*Saved UID*)     | A stored copy of the original EUID that can be restored later.                               | `0` if the binary started with root privileges.    |

---

## 2 SUID permission bit

- SUID is a **special file permission** applied to binaries:  
  ```bash
  chmod u+s file
  ```
- If the file belongs to `root` and has SUID set:
  - **EUID** of the process = UID of the file owner (root).
  - **RUID** stays the same as the user who launched it.

Example:
```bash
-rwsr-xr-x 1 root root ...
```
If `user` (UID 1000) runs it:
- **RUID** = 1000  
- **EUID** = 0  
- **SUID** = 0  

---

## 3 setuid(0) / setgid(0)

A SUID root binary starts with:
```
RUID = your UID   EUID = 0   SUID = 0
```
- Some programs (like `bash`) detect `RUID != 0` and **drop privileges** to avoid security risks.
- Calling:
```c
setuid(0);
setgid(0);
```
sets:
```
RUID = 0   EUID = 0   SUID = 0
```
This ensures:
- The process is **fully root**.
- Any child process (e.g., `/bin/bash`) keeps root privileges.
- At the end of the binary, the process that executes it terminates, and you lose your root privileges. That’s why you need to run another bash process with:
```c
execl("/bin/bash", "bash", "-p", NULL);
```
- If you don’t add `setuid(0)` / `setgid(0)`, `/bin/bash` sees that `RUID ≠ 0` and, for security reasons, may drop its privileges, resulting in a non-root shell.

---

## 4  SUID scripts behave differently

- If a script starts with `#!/bin/bash` (or any interpreter):
  - The kernel launches the **interpreter** as a new process.
  - For security reasons, the kernel **drops the SUID effect** for interpreted scripts.
  - Result: The interpreter runs with the **original user’s UID**, not root.
- That’s why SUID works reliably only with **compiled ELF binaries**.

---

## 5 Special Case: Sudo and Interpreted Scripts

- When running a script with `sudo`, **the interpreter** (e.g., `/bin/bash` in `#!/bin/bash`) is **launched directly by `sudo`** with full root privileges.
- This means:
  ```
  RUID = 0   EUID = 0   SUID = 0
  ```
  → All commands inside the script run as full root.
- Unlike a SUID script (where the kernel strips the SUID bit for security), `sudo` does **not** remove privileges from the interpreter.
- **CTF relevance**: If `sudo -l` allows a script to be executed, you can often exploit it to run arbitrary commands as root.