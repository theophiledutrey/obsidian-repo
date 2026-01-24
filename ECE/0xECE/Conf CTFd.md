## Prérequis host

Sur la machine hôte (Linux) :

```bash
sudo apt update && sudo apt install -y \
  curl \
  unzip \
  kitty-terminfo \
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

Vérification :

```bash
virsh list --all
```

---

## Étape 1 — Installation du plugin CTFd

Dans le repo CTFd :

```bash
cd CTFd/CTFd/plugins
git clone https://github.com/ctfer-io/ctfd-chall-manager.git
```

Penser à changer le nom du plugin: ctfd-chall-manager -> ctfd_chall_manager

---

## Étape 2 — Docker Compose principal (CTFd + Chall-Manager)

### docker-compose.yml (extrait clé)

```yaml

  chall-manager:
    build:
      context: .
      dockerfile: Dockerfile.chall-manager
    restart: always
    environment:
      OCI_INSECURE: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /var/run/libvirt/libvirt-sock:/var/run/libvirt/libvirt-sock
      - /dev/kvm:/dev/kvm

    networks:
      - default
      - internal


  chall-manager-janitor:
    image: ctferio/chall-manager-janitor:v0.6.1
    restart: always
    environment:
      URL: chall-manager:8080
      TICKER: 1m
    depends_on:
      - chall-manager
    networks:
      - default
      - internal


  registry:
    image: registry:2
    restart: always
    ports:
      - 5000:5000
    networks:
      - default
      - internal
```

 **Important** : `PLUGIN_SETTINGS_CM_API_URL=http://chall-manager:8080` dans le service `ctfd`

---

##  Étape 3 — Dockerfile chall-manager custom

### Dockerfile.chall-manager

```dockerfile
FROM ctferio/chall-manager:v0.6.1

USER root


RUN apt-get update && apt-get install -y \
    libvirt-clients \
    libvirt-daemon-system \
    qemu-kvm \
    genisoimage \
    xorriso \
    openssh-client \
    curl \
    ca-certificates \
    unzip \
    && rm -rf /var/lib/apt/lists/*


ENV TERRAFORM_VERSION=1.7.5

RUN curl -fsSL https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip -o /tmp/terraform.zip \
    && unzip /tmp/terraform.zip -d /usr/local/bin \
    && rm /tmp/terraform.zip
```

---

##  Étape 4 — Build & run

```bash
docker compose down
docker compose build --no-cache chall-manager
docker compose up -d
```

Vérifications :

```bash
docker exec -it ctfd-chall-manager-1 terraform --version
docker exec -it ctfd-chall-manager-1 mkisofs --version
docker exec -it ctfd-chall-manager-1 virsh list --all
```

---

##  Étape 5 — Création du scénario (docker-scenario)

### Arborescence

```
hack/docker-scenario/
├── main.go
├── main.tf
├── cloud_init.cfg
├── terraform.tfvars
├── Pulumi.yaml
├── build.sh
```

---

## main.go 

```go
package main

import (
	"fmt"
	"strings"

	"github.com/ctfer-io/chall-manager/sdk"
	localcmd "github.com/pulumi/pulumi-command/sdk/go/command/local"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func main() {
	sdk.Run(func(req *sdk.Request, resp *sdk.Response, opts ...pulumi.ResourceOption) error {
		identity := req.Config.Identity
		workdir := fmt.Sprintf("/tmp/challmgr-%s", identity)

		applyCmd := fmt.Sprintf(`set -euo pipefail
WORK="%s"
mkdir -p "$WORK"

# Copy only what terraform needs into per-instance workdir
cp -f ./main.tf "$WORK/main.tf"
cp -f ./cloud_init.cfg "$WORK/cloud_init.cfg"
cp -f ./terraform.tfvars "$WORK/terraform.tfvars"

cd "$WORK"
terraform init -input=false -no-color
terraform apply -auto-approve -input=false -no-color \
  -var "instance_id=%s" \
  -var-file="terraform.tfvars"
`, workdir, identity)

		destroyCmd := fmt.Sprintf(`set -euo pipefail
WORK="%s"
cd "$WORK"
terraform destroy -auto-approve -input=false -no-color \
  -var "instance_id=%s" \
  -var-file="terraform.tfvars"
`, workdir, identity)

		tfApply, err := localcmd.NewCommand(req.Ctx, "terraform-apply", &localcmd.CommandArgs{
			Create:      pulumi.String(applyCmd),
			Delete:      pulumi.String(destroyCmd),
			Interpreter: pulumi.StringArray{pulumi.String("/bin/bash"), pulumi.String("-c")},
		}, opts...)
		if err != nil {
			return err
		}

		sshOutCmd := fmt.Sprintf(`set -euo pipefail
cd "%s"
terraform output -raw ssh_command -no-color
`, workdir)

		tfOut, err := localcmd.NewCommand(req.Ctx, "terraform-output-ssh", &localcmd.CommandArgs{
			Create:      pulumi.String(sshOutCmd),
			Interpreter: pulumi.StringArray{pulumi.String("/bin/bash"), pulumi.String("-c")},
		}, pulumi.DependsOn([]pulumi.Resource{tfApply}))
		if err != nil {
			return err
		}

		resp.ConnectionInfo = tfOut.Stdout.ApplyT(func(s string) string {
			return strings.TrimSpace(s)
		}).(pulumi.StringOutput)

		return nil
	})
}
```

## main.tf

```terraform
terraform {
  required_providers {
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "0.7.6"
    }
  }
}

provider "libvirt" {
  uri = "qemu:///system"
}

variable "instance_id" {
  type        = string
  description = "Unique instance ID (provided by Chall-Manager)"
}

variable "chall1_passwd" {
  type        = string
  description = "Hashed password for chall1 (cloud-init compatible hash)"
}

locals {
  vm_name      = "chall1-${var.instance_id}"
  volume_name  = "ubuntu-22.04-${var.instance_id}.qcow2"
  cloudinit_iso = "cloudinit-${var.instance_id}.iso"
}

resource "libvirt_volume" "ubuntu_image" {
  name   = local.volume_name
  pool   = "default"
  source = "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
  format = "qcow2"
}

resource "libvirt_cloudinit_disk" "commoninit" {
  name = local.cloudinit_iso
  pool = "default"

  user_data = templatefile("${path.module}/cloud_init.cfg", {
    chall1_passwd = var.chall1_passwd
  })
}

resource "libvirt_domain" "vm" {
  name   = local.vm_name
  memory = 2048
  vcpu   = 2

  disk {
    volume_id = libvirt_volume.ubuntu_image.id
  }

  network_interface {
    network_name   = "default"
    wait_for_lease = true
  }

  cloudinit = libvirt_cloudinit_disk.commoninit.id
}

output "ip" {
  value = libvirt_domain.vm.network_interface[0].addresses[0]
}

output "ssh_command" {
  value = "ssh chall1@${libvirt_domain.vm.network_interface[0].addresses[0]}"
}
```

## cloud_init.cfg

```
#cloud-config

ssh_pwauth: true
disable_root: true

users:
  - name: chall1
    groups: users
    shell: /bin/bash
    lock_passwd: false
    passwd: ${chall1_passwd}

package_update: true
packages:
  - vim
  - sudo
  - kitty-terminfo

write_files:
  - path: /etc/sudoers.d/chall1
    permissions: "0440"
    content: |
      chall1 ALL=(root) NOPASSWD:/usr/bin/vim

  - path: /root/flag.txt
    permissions: "0600"
    content: |
      0xECE{V1m_Pr1v3sc_1s_Tr1v14l}

runcmd:
  - systemctl restart ssh
```

## terraform.tfvars

```
chall1_passwd = "$6$x0XKGtUkYGmgT0oX$NtEUYDjwmZJizWtw.X97RthISFsKNF8g1hirmkqhsGQociJ3aOeDgshyCqwNtgwiPFwxGFW2QDUXmw.T5EX9O."
```

## build.sh

```bash
#!/bin/bash
set -euo pipefail

CGO_ENABLED=0 go build -o main main.go

REGISTRY=${REGISTRY:-"localhost:5000/"}
SCENARIO_REF="${REGISTRY}examples/terraform-libvirt:latest"

cp Pulumi.yaml Pulumi.yaml.bkp
yq e -i '.runtime = {"name": "go", "options": {"binary": "./main"}}' Pulumi.yaml

oras push --insecure \
  "${SCENARIO_REF}" \
  --artifact-type application/vnd.ctfer-io.scenario \
  main:application/vnd.ctfer-io.file \
  Pulumi.yaml:application/vnd.ctfer-io.file \
  main.tf:application/vnd.ctfer-io.file \
  cloud_init.cfg:application/vnd.ctfer-io.file \
  terraform.tfvars:application/vnd.ctfer-io.file

rm -f main
mv Pulumi.yaml.bkp Pulumi.yaml

echo "Pushed scenario: ${SCENARIO_REF}"
```

```
curl -L -o oras.tar.gz https://github.com/oras-project/oras/releases/download/v1.1.0/oras_1.1.0_linux_amd64.tar.gz
```

```
tar -xzf oras.tar.gz
sudo mv oras /usr/local/bin/
oras version
```

```bash
bash build.sh
```

---

##  Étape 6 — Création du challenge dans CTFd

- Type : **Dynamic / Chall-Manager**
- Scenario :

```
registry:5000/privesc/chall-<id>
```

---

## Étape 7 — Création des dépendances Terraform

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
sudo virsh -c qemu:///system pool-list --all
```

```
sudo virsh -c qemu:///system net-list --all
```

```
ls /usr/share/libvirt/networks/default.xml
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
sudo virsh -c qemu:///system net-list --all
```

```
sudo systemctl enable --now libvirtd
```


##  Étape 8 — Lancement d’une instance

Dans CTFd → **Launch instance**

Sur le host :

```bash
virsh list --all
```

Résultat attendu :

```
chall1-<id>   running
```

---


