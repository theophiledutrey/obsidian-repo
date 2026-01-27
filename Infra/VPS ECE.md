```
export TERM=xterm
```

```
theo_admin@0xece:~/terraform$ ls
cloud_init.cfg  main.tf  terraform.tfvars

theo_admin@0xece:~/terraform$ pwd
/home/theo_admin/terraform
```

```
sudo apt update && sudo apt install -y \
  qemu-kvm \
  libvirt-daemon-system \
  libvirt-clients \
  virtinst \
  bridge-utils \
  ca-certificates \
  gnupg \
  lsb-release \
  genisoimage
```

```
curl -LO https://releases.hashicorp.com/terraform/1.8.5/terraform_1.8.5_linux_amd64.zip
```

```
sudo apt install -y unzip
```

```
unzip terraform_1.8.5_linux_amd64.zip
```

```
sudo mv terraform /usr/local/bin/
```

```
sudo chmod +x /usr/local/bin/terraform
```

```
sudo mkdir -p /var/lib/libvirt/images
```

```
sudo virsh -c qemu:///system pool-define-as default dir - - - - "/var/lib/libvirt/images"
```

```
sudo virsh -c qemu:///system pool-start default
```

```
sudo virsh -c qemu:///system pool-autostart default
```

```
sudo virsh -c qemu:///system net-define /usr/share/libvirt/networks/default.xml
```

```
sudo virsh -c qemu:///system net-start default
```

```
sudo virsh -c qemu:///system net-autostart default
```

```
sudo systemctl enable --now libvirtd
```

```
sudo usermod -aG libvirt $USER
sudo usermod -aG kvm $USER
```

```
sudo nano /etc/libvirt/qemu.conf

user = "libvirt-qemu"
group = "kvm"
dynamic_ownership = 1
security_driver = "none"
namespaces = []
```

```
theo_admin@0xece:/var/www/0xece$ sudo ufw default allow routed
Default routed policy changed to 'allow'
(be sure to update your rules accordingly)
theo_admin@0xece:/var/www/0xece$ sudo ufw reload
Firewall reloaded

theo_admin@0xece:/var/www/0xece$ sudo ufw allow 30000:40000/tcp
Rule added
Rule added (v6)
theo_admin@0xece:/var/www/0xece$ sudo ufw reload
Firewall reloaded
```

```
sudo iptables -L FORWARD -n -v --line-numbers
sudo iptables -t nat -L -n -v | grep 22
```