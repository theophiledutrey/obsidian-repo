## Prérequis host

Sur la machine hôte (Linux) :

```bash
sudo apt update && sudo apt install -y \
  qemu-kvm \
  libvirt-daemon-system \
  libvirt-clients \
  virtinst \
  bridge-utils \
  ca-certificates \
  gnupg \
  lsb-release \
  genisoimage \
  golang
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
docker exec -it 0xece-chall-manager-1 terraform --version
docker exec -it 0xece-chall-manager-1 mkisofs --version
docker exec -it 0xece-chall-manager-1 virsh list --all
```

---

##  Étape 5 — Création du scénario (docker-scenario)

### Arborescence

```
hack/docker-scenario/
├── build_all.sh
├── chall-1/
│   ├── build.sh
│   ├── main.go
│   ├── go.mod
│   ├── go.sum
│   ├── main.tf
│   ├── cloud_init.cfg
│   ├── terraform.tfvars
│   └── Pulumi.yaml
├── chall-2/
│   ├── build.sh
│   ├── main.go
│   ├── go.mod
│   ├── go.sum
│   ├── main.tf
│   ├── cloud_init.cfg
│   ├── terraform.tfvars
│   └── Pulumi.yaml
├── chall-3/
│   ├── build.sh
│   ├── main.go
│   ├── go.mod
│   ├── go.sum
│   ├── main.tf
│   ├── cloud_init.cfg
│   ├── terraform.tfvars
│   └── Pulumi.yaml
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

### chall 1: 

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
  type   = "qemu"
  emulator = "/usr/bin/qemu-system-x86_64" 
  
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

### chall 2:

```
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

############################
# Variables Chall-Manager
############################

variable "instance_id" {
  type        = string
  description = "Unique instance ID (provided by Chall-Manager)"
}

variable "chall2_passwd" {
  type        = string
  description = "Hashed password for chall2 (cloud-init compatible hash)"
}

############################
# Locals
############################

locals {
  vm_name        = "chall2-${var.instance_id}"
  base_volume    = "ubuntu-22.04-base-${var.instance_id}.qcow2"
  root_volume    = "ubuntu-22.04-chall2-root-${var.instance_id}.qcow2"
  cloudinit_iso  = "cloudinit-chall2-${var.instance_id}.iso"
}

############################
# Base image
############################

resource "libvirt_volume" "ubuntu_image" {
  name   = local.base_volume
  pool   = "default"
  source = "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
  format = "qcow2"
}

############################
# Root disk (expanded)
############################

resource "libvirt_volume" "ubuntu_root" {
  name           = local.root_volume
  pool           = "default"
  base_volume_id = libvirt_volume.ubuntu_image.id
  size           = 10 * 1024 * 1024 * 1024
}

############################
# Cloud-init
############################

resource "libvirt_cloudinit_disk" "commoninit" {
  name = local.cloudinit_iso
  pool = "default"

  user_data = templatefile("${path.module}/cloud_init.cfg", {
    chall2_passwd = var.chall2_passwd
  })
}

############################
# VM
############################

resource "libvirt_domain" "vm" {
  name   = local.vm_name
  memory = 2048
  vcpu   = 2
  type   = "qemu"
  emulator = "/usr/bin/qemu-system-x86_64" 
  
  disk {
    volume_id = libvirt_volume.ubuntu_root.id
  }

  network_interface {
    network_name   = "default"
    wait_for_lease = true
  }

  cloudinit = libvirt_cloudinit_disk.commoninit.id
}

############################
# Outputs (CTFd display)
############################

output "ip" {
  value = libvirt_domain.vm.network_interface[0].addresses[0]
}

output "ssh_command" {
  value = "ssh chall2@${libvirt_domain.vm.network_interface[0].addresses[0]}"
}
```

### chall 3:

```
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

############################
# Variables Chall-Manager
############################

variable "instance_id" {
  type        = string
  description = "Unique instance ID (provided by Chall-Manager)"
}

variable "chall3_passwd" {
  type        = string
  description = "Hashed password for chall3 (cloud-init compatible hash)"
}

############################
# Locals
############################

locals {
  vm_name       = "chall3-${var.instance_id}"
  base_volume   = "ubuntu-22.04-base-${var.instance_id}.qcow2"
  root_volume   = "ubuntu-22.04-chall3-root-${var.instance_id}.qcow2"
  cloudinit_iso = "cloudinit-chall3-${var.instance_id}.iso"
}

############################
# Base image
############################

resource "libvirt_volume" "ubuntu_image" {
  name   = local.base_volume
  pool   = "default"
  source = "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
  format = "qcow2"
}

############################
# Root disk (expanded)
############################

resource "libvirt_volume" "ubuntu_root" {
  name           = local.root_volume
  pool           = "default"
  base_volume_id = libvirt_volume.ubuntu_image.id
  size           = 10 * 1024 * 1024 * 1024
}

############################
# Cloud-init
############################

resource "libvirt_cloudinit_disk" "commoninit" {
  name = local.cloudinit_iso
  pool = "default"

  user_data = templatefile("${path.module}/cloud_init.cfg", {
    chall3_passwd = var.chall3_passwd
  })
}

############################
# VM
############################

resource "libvirt_domain" "vm" {
  name   = local.vm_name
  memory = 2048
  vcpu   = 2
  type   = "qemu"
  emulator = "/usr/bin/qemu-system-x86_64" 
  
  disk {
    volume_id = libvirt_volume.ubuntu_root.id
  }

  network_interface {
    network_name   = "default"
    wait_for_lease = true
  }

  cloudinit = libvirt_cloudinit_disk.commoninit.id
}

############################
# Outputs (CTFd display)
############################

output "ip" {
  value = libvirt_domain.vm.network_interface[0].addresses[0]
}

output "ssh_command" {
  value = "ssh chall3@${libvirt_domain.vm.network_interface[0].addresses[0]}"
}
```
## cloud_init.cfg

### chall 1:

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

### chall 2:

```
#cloud-config

ssh_pwauth: true
disable_root: true

users:
  - name: chall2
    groups: users, netdata
    shell: /bin/bash
    lock_passwd: false
    passwd: ${chall2_passwd}

packages:
  - sudo
  - gcc
  - make
  - build-essential
  - jq
  - tar
  - kitty-terminfo

write_files:
  # -------------------------
  # Source C d'un "ndsudo" vulnérable (PATH-based exec)
  # - SetUID root
  # - whitelisting "commande" MAIS exécutable résolu via execvp => PATH hijack
  # -------------------------
  - path: /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo.c
    permissions: '0644'
    content: |
      #define _GNU_SOURCE
      #include <stdio.h>
      #include <stdlib.h>
      #include <string.h>
      #include <unistd.h>
      #include <errno.h>

      static void usage(void) {
        puts("ndsudo\n");
        puts("(C) Netdata Inc.\n");
        puts("A helper to allow Netdata run privileged commands.\n");
        puts("  --test");
        puts("    print the generated command that will be run, without running it.\n");
        puts("  --help");
        puts("    print this message.\n");
        puts("The following commands are supported:\n");
        puts("- Command    : nvme-list");
        puts("  Executables: nvme");
        puts("  Parameters : list --output-format=json\n");
        puts("- Command    : nvme-smart-log");
        puts("  Executables: nvme");
        puts("  Parameters : smart-log --output-format=json\n");
        puts("The program searches for executables in the system path.\n");
      }

      static int is_flag(const char *s, const char *f) {
        return s && f && strcmp(s, f) == 0;
      }

      int main(int argc, char **argv) {
        int test = 0;
        int i = 1;

        if (argc < 2) {
          usage();
          return 1;
        }

        if (is_flag(argv[i], "--help") || is_flag(argv[i], "-h")) {
          usage();
          return 0;
        }

        if (is_flag(argv[i], "--test")) {
          test = 1;
          i++;
          if (argc <= i) {
            usage();
            return 1;
          }
        }

        const char *cmd = argv[i++];

        // Whitelist logique, mais exécution via PATH => vulnérable
        const char *exe = NULL;
        const char *p1  = NULL;
        const char *p2  = NULL;

        if (strcmp(cmd, "nvme-list") == 0) {
          exe = "nvme";
          p1  = "list";
          p2  = "--output-format=json";
        } else if (strcmp(cmd, "nvme-smart-log") == 0) {
          exe = "nvme";
          p1  = "smart-log";
          p2  = "--output-format=json";
        } else {
          fprintf(stderr, "Unknown command: %s\n", cmd);
          return 1;
        }

        // Génère argv pour execvp(exe, ...)
        char *args[6];
        int n = 0;
        args[n++] = (char*)exe;
        args[n++] = (char*)p1;
        args[n++] = (char*)p2;
        args[n]   = NULL;

        if (test) {
          // Simule le message "not available in PATH"
          if (access(exe, X_OK) != 0 && errno == ENOENT) {
            fprintf(stderr, "%s : not available in PATH.\n", exe);
            return 1;
          }
          printf("%s %s %s\n", exe, p1, p2);
          return 0;
        }

        // SetUID root + execvp => PATH search (le cœur du chall)
        execvp(exe, args);
        perror("execvp");
        return 1;
      }

  # -------------------------
  # Flag root
  # -------------------------
  - path: /root/flag.txt
    permissions: '0600'
    content: |
      0xECE{P4TH_H1J4CK_W1TH_S3TU1D}

runcmd:
  # Groupe netdata + arbo "netdata-like"
  - groupadd -f netdata
  - mkdir -p /opt/netdata/usr/libexec/netdata/plugins.d

  # Compile ndsudo
  - gcc /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo.c -o /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo

  # Permissions: SetUID root, exécutable par groupe netdata uniquement
  - chown root:netdata /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
  - chmod 4750 /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo

  # Un petit “leurre” de dossier où le joueur peut dropper des binaires
  - mkdir -p /dev/shm
  - chown -R chall2:chall2 /dev/shm

  # Home dummy + permissions
  - mkdir -p /home/chall2
  - chown -R chall2:chall2 /home/chall2
  - rm -f /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo.c

  # SSH
  - systemctl restart ssh
```

### chall 3:

```
#cloud-config

ssh_pwauth: true
disable_root: true

users:
  - name: chall3
    groups: users
    shell: /bin/bash
    lock_passwd: false
    passwd: ${chall3_passwd}

packages:
  - sudo
  - kitty-terminfo
  - jq
  - tar

bootcmd:
  - mkdir -p /home/chall3/backups
  - chown chall3:chall3 /home/chall3/backups

write_files:

  # -------------------------
  # Script vulnérable backy.sh (TOCTOU)
  # -------------------------
  - path: /usr/bin/backy.sh
    permissions: '0755'
    content: |
      #!/bin/bash

      if [[ $# -ne 1 ]]; then
        /usr/bin/echo "Usage: $0 <task.json>"
        exit 1
      fi

      json_file="$1"

      if [[ ! -f "$json_file" ]]; then
        /usr/bin/echo "Error: File '$json_file' not found."
        exit 1
      fi

      allowed_paths=("/var/" "/home/")

      directories_to_archive=$(/usr/bin/jq -r '.directories_to_archive[]' "$json_file")

      is_allowed_path() {
        local path="$1"
        for allowed in "$${allowed_paths[@]}"; do
          if [[ "$path" == "$allowed"* ]]; then
            return 0
          fi
        done
        return 1
      }

      for dir in $directories_to_archive; do
        real_dir=$(/usr/bin/realpath "$dir" 2>/dev/null)

        if [[ -z "$real_dir" ]]; then
          /usr/bin/echo "Error: Invalid path $dir"
          exit 1
        fi

        if ! is_allowed_path "$real_dir"; then
          /usr/bin/echo "Error: $real_dir is not allowed. Only /var/ and /home/ allowed."
          exit 1
        fi
      done

      exec /usr/bin/backy "$json_file"


  # -------------------------
  # Programme root d'archivage
  # -------------------------
  - path: /usr/bin/backy
    permissions: '0755'
    content: |
      #!/bin/bash

      json="$1"

      log() {
        echo "$(date '+%Y/%m/%d %H:%M:%S') $1"
      }

      log "🍀 backy 1.2"
      log "📋 Working with $json ..."

      dest=$(jq -r '.destination' "$json")
      dirs=$(jq -r '.directories_to_archive[]' "$json")

      if [[ -z "$dirs" ]]; then
        log "💤 Nothing to sync"
        exit 0
      fi

      log "📤 Archiving: [$dirs]"
      log "📥 To: $dest ..."

      mkdir -p "$dest"

      # Archivage propre (TOCTOU toujours exploitable)
      tar -cf "$dest/backup.tar" -C / $${dirs#/}

      log "📦 Done"


  # -------------------------
  # Désactivation de use_pty pour chall3 (comportement HTB)
  # -------------------------
  - path: /etc/sudoers.d/chall3
    permissions: '0440'
    content: |
      Defaults:chall3 


  # -------------------------
  # Sudoers : chall3 peut lancer backy.sh en root
  # -------------------------
  - path: /etc/sudoers.d/chall3
    permissions: '0440'
    content: |
      chall3 ALL=(root) NOPASSWD:/usr/bin/backy.sh


  # -------------------------
  # Template officiel task.json
  # -------------------------
  - path: /home/chall3/backups/task.json
    permissions: '0644'
    content: |
      {
        "destination": "/home/chall3/backups/",
        "multiprocessing": true,
        "verbose_log": false,
        "directories_to_archive": [
          "/home/app-production/app"
        ],
        "exclude": [
          ".*"
        ]
      }


  # -------------------------
  # Flag root
  # -------------------------
  - path: /root/flag.txt
    permissions: '0600'
    content: |
     0xECE{R4C3_W1NS_B3F0R3_CH3CK}


runcmd:
  - mkdir -p /home/app-production/app
  - echo "dummy file" > /home/app-production/app/readme.txt
  - chown -R chall3:chall3 /home/chall3
  - chmod +x /usr/bin/backy.sh /usr/bin/backy
  - systemctl restart ssh
  - sed -i '/Defaults.*use_pty/d' /etc/sudoers
  - sed -i '/Defaults.*use_pty/d' /etc/sudoers.d/*
```

## terraform.tfvars

### chall 1:

```
chall1_passwd = "$6$x0XKGtUkYGmgT0oX$NtEUYDjwmZJizWtw.X97RthISFsKNF8g1hirmkqhsGQociJ3aOeDgshyCqwNtgwiPFwxGFW2QDUXmw.T5EX9O."
```

### chall 2:

```
chall2_passwd = "$6$e9mTM0WWsOiUo9hA$57o5CXukezB/HK6DdZtDPyOUl6cBsEzKbnn.PErlNhpS0eH6HU0Esx8AvwxdC7EpKkbvkuCjY455laorcK63L."
```

### chall 3:

```
chall3_passwd = "$6$MF.lPeW6LXASpdg8$MudHc/CcSYxWvsWzZ31MrD0Os5T9qAhgHczi6c6bkENmzRePVyGselbO43CaQcOqPjVZ52.4A4K6dzGON./vp/"
```
## build.sh

```bash
#!/bin/bash
set -euo pipefail

CGO_ENABLED=0 go build -o main main.go

REGISTRY=${REGISTRY:-"localhost:5000/"}
SCENARIO_REF="${REGISTRY}privesc/chall-<id>:latest"

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

---
## build_all.sh

```bash
#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Building all challenge scenarios..."
echo "Root directory: $ROOT_DIR"
echo

CHALLS=(
  "chall-1"
  "chall-2"
  "chall-3"
)

for chall in "${CHALLS[@]}"; do
  echo "=============================="
  echo "Building $chall"
  echo "=============================="

  (
    cd "$ROOT_DIR/$chall"
    bash build.sh
  )

  echo "$chall done"
  echo
done

echo "All scenarios built and pushed successfully"
```

```
curl -L -o oras.tar.gz https://github.com/oras-project/oras/releases/download/v1.1.0/oras_1.1.0_linux_amd64.tar.gz
```

```
tar -xzf oras.tar.gz
sudo mv oras /usr/local/bin/
oras version
```

```
sudo wget -O /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64
sudo chmod +x /usr/local/bin/yq
```

```bash
bash build_all.sh
```

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

---


```
  chall-manager:
    build:
      context: .
      dockerfile: Dockerfile.chall-manager
    restart: always
    privileged: true
    cap_add:
      - SYS_ADMIN
      - NET_ADMIN
    devices:
      - /dev/kvm:/dev/kvm
    environment:
      OCI_INSECURE: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /var/run/libvirt/libvirt-sock:/var/run/libvirt/libvirt-sock
    networks:
      - default
      - challenges_internal


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
      - challenges_internal


  registry:
    image: registry:2
    restart: always
    ports:
      - 5000:5000
    networks:
      - default
      - challenges_internal
        
  scenario-builder:
    image: golang:1.24-bookworm
    depends_on:
      - registry
    environment:
      REGISTRY: registry:5000/
    volumes:
      - ./.data/CTFd/plugins/ctfd_chall_manager/hack/docker-scenario:/scenarios
    working_dir: /scenarios
    entrypoint:
      - /bin/bash
      - /scenarios/build_all_container.sh
    restart: "no"
```