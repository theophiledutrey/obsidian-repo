# 🧠 CTFd + Chall-Manager + Terraform + Libvirt (Guide complet)

> Fiche **pas à pas**, reproductible à l’identique, basée sur une installation fonctionnelle validée.  
> Formaté pour **Obsidian** (Markdown).

---

## 🎯 Objectif

Mettre en place une plateforme CTF capable de :

- Déployer **dynamiquement des VM par joueur**
    
- Via **CTFd + CTFd-Chall-Manager**
    
- En utilisant **Terraform + libvirt/KVM**
    
- Avec **cloud-init** pour la configuration initiale
    
- Nettoyage automatique via **Janitor**
    

---

## 🧱 Architecture finale

```
CTFd (UI)
  │
  ├── Plugin ctfd-chall-manager
  │       │
  │       └── Chall-Manager (API)
  │               ├── Terraform
  │               ├── libvirt (socket host)
  │               ├── mkisofs / cloud-init
  │               └── Registry OCI
  │
  └── MySQL / Redis / Nginx

VMs libvirt (sur le host)
```

---

## ⚙️ Prérequis host

Sur la machine hôte (Linux) :

```bash
sudo apt install -y \
  qemu-kvm \
  libvirt-daemon-system \
  libvirt-clients \
  virtinst \
  bridge-utils

sudo systemctl enable --now libvirtd
```

Vérification :

```bash
virsh list --all
```

---

## 📦 Étape 1 — Installation du plugin CTFd

Dans le repo CTFd :

```bash
cd CTFd/CTFd/plugins
git clone https://github.com/ctfer-io/ctfd-chall-manager.git
```

Puis redémarrage :

```bash
docker compose down
docker compose up -d
```

---

## 🧩 Étape 2 — Docker Compose principal (CTFd + Chall-Manager)

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
```

⚠️ **Important** : `PLUGIN_SETTINGS_CM_API_URL=http://chall-manager:8080` dans le service `ctfd`

---

## 🐳 Étape 3 — Dockerfile chall-manager custom

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

RUN curl -fsSL https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip \
    -o /tmp/terraform.zip \
    && unzip /tmp/terraform.zip -d /usr/local/bin \
    && rm /tmp/terraform.zip
```

---

## 🔨 Étape 4 — Build & run

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

## 📦 Étape 5 — Registry OCI locale

Dans docker-compose :

```yaml
  registry:
    image: registry:2
    ports:
      - 5000:5000
```

Vérification :

```bash
curl http://localhost:5000/v2/_catalog
```

---

## 🧪 Étape 6 — Création du scénario (docker-scenario)

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

## 🧠 main.go (Pulumi / Chall-Manager)

- Utilise `command:local` pour lancer Terraform
    
- Copie les fichiers dans `/tmp/challmgr-<instance_id>`
    
- Exécute :
    

```bash
terraform init
terraform apply -auto-approve
```

- Récupère les outputs (`ip`, `ssh_command`)
    

---

## ☁️ cloud_init.cfg

- Création utilisateur `chall1`
    
- Mot de passe hashé
    
- Installation de packages
    
- Dépôt du flag
    

---

## 🧱 main.tf (Terraform libvirt)

- libvirt_volume (image Ubuntu cloud)
    
- libvirt_cloudinit_disk
    
- libvirt_domain
    
- network `default`
    
- outputs :
    

```hcl
output "ip" {}
output "ssh_command" {}
```

---

## 📤 Étape 7 — Build et push du scénario

### build.sh

```bash
#!/bin/bash

CGO_ENABLED=0 go build -o main main.go
REGISTRY=${REGISTRY:-"localhost:5000/"}

yq e -i '.runtime = {"name": "go", "options": {"binary": "./main"}}' Pulumi.yaml

oras push --insecure \
  "${REGISTRY}examples/terraform-libvirt:latest" \
  --artifact-type application/vnd.ctfer-io.scenario \
  main:application/vnd.ctfer-io.file \
  Pulumi.yaml:application/vnd.ctfer-io.file \
  main.tf:application/vnd.ctfer-io.file \
  cloud_init.cfg:application/vnd.ctfer-io.file \
  terraform.tfvars:application/vnd.ctfer-io.file
```

```bash
bash build.sh
```

---

## 🎮 Étape 8 — Création du challenge dans CTFd

- Type : **Dynamic / Chall-Manager**
    
- Scenario :
    

```
registry:5000/examples/terraform-libvirt:latest
```

- Timeout, until, destroy on flag selon besoin
    

---

## 🚀 Étape 9 — Lancement d’une instance

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

## 🧹 Étape 10 — Cleanup automatique

- Géré par `chall-manager-janitor`
    
- Timeout
    
- Until
    
- Destroy on flag
    

---

## ✅ État final

✔ Infra fonctionnelle  
✔ Multi-instances  
✔ Cloud-init  
✔ Terraform  
✔ Libvirt/KVM  
✔ Nettoyage auto

---

## 🚀 Améliorations possibles

- Mot de passe unique par instance
    
- Affichage IP + SSH dans CTFd
    
- Hardening VM
    
- Réseau isolé par challenge
    
- Export infra en Terraform pur
    

---

## 🏁 Conclusion

Cette stack permet de déployer des **challenges CTF réalistes, isolés et scalables**, comparables aux plateformes professionnelles.

🔥 **Validé et reproductible.**