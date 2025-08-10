## 1. List Disks
```bash
lsblk
```

## 2. Create a Mount Point
```bash
sudo mkdir -p /media/usb
```

## 3. Mount the Disk
```bash
sudo mount /dev/sda1 /media/usb
```

## 4. Auto-Mount on Startup
Edit `/etc/fstab` and add this line:
```
/dev/sda1 /media/usb auto defaults,nofail 0 0
```

## 5. Create a Samba User
```bash
sudo adduser vpnuser
sudo smbpasswd -a vpnuser
```

## 6. Configure Samba for the VPN
Edit Samba configuration:
```bash
sudo nano /etc/samba/smb.conf
```
Add at the bottom:
```
[VPNShare]
   path = /media/usb
   valid users = vpnuser
   read only = no
   browsable = yes
   guest ok = no
   force user = vpnuser
   hosts allow = 10.0.0.0/24
```

## 7. Restart Samba Service
```bash
sudo systemctl restart smbd
```

## 8. Test Connection to the Share (from a VPN client)

### Install CIFS Utilities (Linux)
```bash
sudo apt install cifs-utils
```

### Use a Credentials File
Create `~/.smbcredentials`:
```
username=vpnuser
password=your_password
```

Change permissions:
```bash
chmod 600 ~/.smbcredentials
```

### Mount the Share
```bash
sudo mount -t cifs //10.0.0.1/VPNShare /mnt/vpnshare -o credentials=/home/<your_user>/.smbcredentials
```