When a process runs on Linux, it doesn’t just have UIDs — it can also have **Capabilities**, which define fine-grained privileges normally reserved for `root`.

---

## 1 What are Capabilities?

- Instead of giving a binary **full root powers** (via SUID or UID=0), Linux **splits root privileges into ~40 distinct capabilities**.  
- A process can keep its normal user ID (non-root) but still hold **specific powers** such as:
  - Binding to low ports
  - Opening raw sockets
  - Mounting filesystems
  - Changing file ownerships

This reduces the attack surface: a program only gets the privileges it **really needs**.

---

## 2 Common Capabilities

| Capability              | Meaning                                                           | Example usage                          |
| ----------------------- | ----------------------------------------------------------------- | -------------------------------------- |
| **CAP_NET_BIND_SERVICE** | Open ports <1024                                                  | Run a webserver on port 80 as non-root |
| **CAP_NET_RAW**         | Create raw sockets                                                | `ping` command                         |
| **CAP_CHOWN**           | Change file ownership                                             | `chown` binary                         |
| **CAP_SYS_BOOT**        | Reboot the system                                                 | `reboot` command                       |
| **CAP_SYS_ADMIN**       | "Catch-all" capability: mount, chroot, change system settings     | Almost full root access                |
| **CAP_SETUID**          | Change process UID                                                | Potential privilege escalation          |

---

## 3 Capability Sets

Each process tracks 5 capability sets:

| Set           | Meaning                                                                 |
| ------------- | ----------------------------------------------------------------------- |
| **Permitted** | Capabilities the process may use.                                       |
| **Effective** | Capabilities currently active.                                          |
| **Inheritable** | Capabilities passed to child processes.                               |
| **Bounding**  | Upper limit: capabilities the process can ever gain.                    |
| **Ambient**   | Inheritable without being dropped (for shell-like environments).        |

---

## 4 Managing Capabilities

- View capabilities of a binary:
  ```bash
  getcap /bin/ping
  ```
  Example output:
  ```
  /bin/ping = cap_net_raw+ep
  ```

- Assign a capability:
  ```bash
  sudo setcap cap_net_bind_service+ep /usr/bin/python3
  ```

- Check running process capabilities:
  ```bash
  cat /proc/<PID>/status | grep Cap
  ```

