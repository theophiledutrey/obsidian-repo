##  Find SUID/SGID files

```bash
find / -perm -4000 2>/dev/null
```

> Lists all files with SUID/SGID permissions. These can often be exploited to run programs with elevated privileges. (chmod 4000 for owner and chmod 2000 for group)

## Check sudo rights

```bash
sudo -l
```

> Displays commands the current user can execute via sudo, with or without a password.

## Check Linux capabilities

```bash
getcap -r / 2>/dev/null | grep '/bin/'
```

> Recursively lists files with Linux capabilities, filtered for `/bin`.

## Find files belonging to your group

```bash
id         # check your groups
find / -group yourgroup -type f 2>/dev/null
```

> Search for files owned by a group you are a member of.

## Useful directories to investigate

- `/tmp`, `/var/tmp`, `/var/backups`
- `/var/mail`, `/var/spool/mail`
- `/etc/exports`
- `/opt/`: often used for custom applications

## List open ports

```bash
netstat -tulnp
```

## Port forwarding

```bash
ssh -L 8000:127.0.0.1:8000 enzo@10.10.11.68
```

## AppArmor

- Check AppArmor profiles and restrictions in `/etc/apparmor.d/`

---