Déployer une VM Ubuntu avec Terraform 


---

## Architecture générale

Chaîne réelle utilisée :

Terraform → Provider libvirt → libvirt → démons backend → QEMU/KVM → VM Ubuntu

Sur Fedora 42, libvirt est découpé en plusieurs services indépendants :

- virtqemud : exécution des VM (QEMU/KVM)
- virtstoraged : stockage (volumes, pools)
- virtnetworkd : réseaux virtuels
- virtproxyd : proxy API
- virtlogd : logs
- virtlockd : verrous

Chaque backend doit être installé et démarré séparément.

---

## Initialisation Terraform

```bash
terraform init
```

Rôle :

- Télécharge le provider libvirt
- Initialise l’état Terraform
- Crée `.terraform.lock.hcl`

---

## Installation du backend QEMU

```bash
sudo dnf install -y libvirt-daemon-driver-qemu
```

Rôle :

- Installe le driver libvirt pour QEMU/KVM
- Permet la création des sockets virtqemud

---

## Démarrage du démon QEMU libvirt

```bash
sudo systemctl start virtqemud.service
sudo systemctl restart virtqemud.socket
```

Rôle :

- Lance le backend QEMU
- Crée les sockets :
    - /run/libvirt/virtqemud-sock
    - /run/libvirt/virtqemud-sock-ro
    - /run/libvirt/virtqemud-admin-sock

---

## Vérification des sockets libvirt

```bash
ls -l /run/libvirt/
```

Rôle :

- Vérifier quels backends sont actifs
- Confirmer l’existence des sockets UNIX

---

## Correction du chemin /var/run

```bash
sudo ln -s /run/libvirt /var/run/libvirt
```

Rôle :

- Corrige le chemin attendu par virsh
- Fedora 42 n’a pas toujours le symlink /var/run → /run

---

## Installation du backend stockage libvirt

```bash
sudo dnf install -y libvirt-daemon-driver-storage
```

Rôle :

- Installe les drivers de stockage libvirt
- Nécessaire pour créer pools et volumes

---

## Démarrage du démon stockage

```bash
sudo systemctl enable --now virtstoraged.socket
sudo systemctl enable --now virtstoraged.service
```

Rôle :

- Lance le backend stockage
- Crée les sockets :
    - virtstoraged-sock
    - virtstoraged-sock-ro
    - virtstoraged-admin-sock

---

## Création du pool de stockage default

```bash
sudo virsh -c qemu:///system pool-define-as default dir - - - - "/var/lib/libvirt/images"
sudo virsh -c qemu:///system pool-start default
sudo virsh -c qemu:///system pool-autostart default
```

Rôle :

- Déclare un pool de stockage nommé `default`
- Démarre le pool
- Active le démarrage automatique

---

## Installation du backend réseau libvirt

```bash
sudo dnf install -y libvirt-daemon-driver-network
```

Rôle :

- Installe les drivers réseau libvirt
- Nécessaire pour créer des réseaux virtuels

---

## Démarrage du démon réseau

```bash
sudo systemctl enable --now virtnetworkd.socket
sudo systemctl enable --now virtnetworkd.service
```

Rôle :

- Lance le backend réseau
- Crée les sockets :
    - virtnetworkd-sock
    - virtnetworkd-sock-ro
    - virtnetworkd-admin-sock

---

## Création du réseau virtuel default

Création du fichier XML :

```bash
sudo nano /tmp/default-network.xml
```

Contenu :

```xml
<network>
  <name>default</name>
  <forward mode='nat'/>
  <bridge name='virbr0' stp='on' delay='0'/>
  <ip address='192.168.122.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.122.100' end='192.168.122.254'/>
    </dhcp>
  </ip>
</network>
```

Déclaration et activation :

```bash
sudo virsh -c qemu:///system net-define /tmp/default-network.xml
sudo virsh -c qemu:///system net-start default
sudo virsh -c qemu:///system net-autostart default
```

Rôle :

- Crée un réseau NAT
- Active DHCP
- Permet aux VM d’avoir une IP

---

## Vérifications libvirt

```bash
virsh -c qemu:///system pool-list --all
virsh -c qemu:///system net-list --all
virsh -c qemu:///system list --all
```

Rôle :

- Vérifier :
    - le pool de stockage
    - le réseau virtuel
    - les VM existantes

---

## Déploiement Terraform

```bash
terraform apply
```

Rôle :

- Télécharge l’image Ubuntu
- Crée le volume qcow2
- Crée la VM Ubuntu
- Attache le disque
- Connecte la VM au réseau default
- Démarre la VM

---

## Ce que Terraform a créé

Volume :

- Fichier : /var/lib/libvirt/images/ubuntu-22.04.qcow2
- Source : image cloud Ubuntu 22.04

Domaine libvirt :

- Nom : ubuntu-tf
- RAM : 2048 Mo
- vCPU : 2
- Réseau : default
- Disque : ubuntu-22.04.qcow2

---

## Pipeline réel

```
Terraform  
↓  
Provider libvirt  
↓  
libvirt API  
↓  
virtqemud → QEMU/KVM  
virtstoraged → stockage  
virtnetworkd → réseau  
↓  
VM Ubuntu
```




## Fichier Terraform `main.tf`

```hcl
terraform {
  required_providers {
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "~> 0.7"
    }
  }
}

provider "libvirt" {
  uri = "qemu:///system"
}

resource "libvirt_volume" "ubuntu_image" {
  name   = "ubuntu-22.04.qcow2"
  pool   = "default"
  source = "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
  format = "qcow2"
}

resource "libvirt_domain" "ubuntu_vm" {
  name   = "ubuntu-tf"
  memory = 2048
  vcpu   = 2

  disk {
    volume_id = libvirt_volume.ubuntu_image.id
  }

  network_interface {
    network_name = "default"
  }

  graphics {
    type           = "spice"
    listen_type    = "address"
    listen_address = "127.0.0.1"
  }
}
```
### Bloc `terraform`

```hcl
terraform {
  required_providers {
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "~> 0.7"
    }
  }
}
```

Déclare le provider utilisé par Terraform.
- `dmacvicar/libvirt` : plugin Terraform pour parler à libvirt
- `version ~> 0.7` : accepte toute version compatible 0.7.x
- 
### Bloc `provider "libvirt"`

```hcl
provider "libvirt" {
  uri = "qemu:///system"
}
```

Indique à Terraform où se trouve l’hyperviseur.

- `qemu:///system` :
    - connexion système (root) à libvirt
    - permet de gérer réseaux, pools et VMs globales

### Ressource `libvirt_volume`

```hcl
resource "libvirt_volume" "ubuntu_image" {
  name   = "ubuntu-22.04.qcow2"
  pool   = "default"
  source = "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
  format = "qcow2"
}
```

Crée un disque virtuel dans libvirt
- `name` : nom du fichier dans le pool de stockage
- `pool` : pool libvirt utilisé (`default` → /var/lib/libvirt/images)
- `source` : image cloud Ubuntu officielle
- `format` : format disque qcow2

Terraform télécharge automatiquement l’image et la stocke localement.

### Ressource `libvirt_domain`

```hcl
resource "libvirt_domain" "ubuntu_vm" {
  name   = "ubuntu-tf"
  memory = 2048
  vcpu   = 2

  disk {
    volume_id = libvirt_volume.ubuntu_image.id
  }

  network_interface {
    network_name = "default"
  }

  graphics {
    type           = "spice"
    listen_type    = "address"
    listen_address = "127.0.0.1"
  }
}
```

Crée la machine virtuelle.

- `name` : nom de la VM dans libvirt
- `memory` : RAM en Mo
- `vcpu` : nombre de CPU virtuels
#### Bloc `disk`

Lie la VM au disque créé précédemment.
- `volume_id` : référence au volume Terraform
#### Bloc `network_interface`

Connecte la VM au réseau libvirt `default`.
- NAT automatique vers Internet
- attribution DHCP automatique
#### Bloc `graphics`

Active l’affichage graphique.

- `type = spice` : protocole graphique
- `listen_address = 127.0.0.1` : accès local uniquement
