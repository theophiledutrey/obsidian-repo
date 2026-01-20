# Cheat-sheet Terraform + libvirt


---

## 1) Commandes Terraform

### Initialiser un projet Terraform

```bash
terraform init
```

---

### Voir ce que Terraform va faire

```bash
terraform plan
```

---

### Créer ou mettre à jour l’infrastructure

```bash
terraform apply
```

---

### Détruire toute l’infrastructure gérée par Terraform

```bash
terraform destroy
```

---

### Forcer la recréation d’une ressource

```bash
terraform taint libvirt_domain.ubuntu_vm
terraform apply
```

---
### Voir l’état Terraform

```bash
terraform state list
terraform state show libvirt_domain.ubuntu_vm
```

---

## 2) Commandes libvirt (virsh)

### Lister toutes les VMs

```bash
virsh -c qemu:///system list --all
```

---

### Démarrer une VM

```bash
virsh -c qemu:///system start ubuntu-tf
```

---

### Arrêter proprement une VM

```bash
virsh -c qemu:///system shutdown ubuntu-tf
```

---

### Forcer l’arrêt d’une VM

```bash
virsh -c qemu:///system destroy ubuntu-tf
```

---

### Redémarrer une VM

```bash
virsh -c qemu:///system reboot ubuntu-tf
```

---

### Supprimer une VM côté libvirt uniquement

```bash
virsh -c qemu:///system undefine ubuntu-tf
```

---

### Voir l’adresse IP d’une VM

```bash
virsh -c qemu:///system domifaddr ubuntu-tf
```
ou 
```
virsh -c qemu:///system net-dhcp-leases default
```

---

### Ouvrir la console série d’une VM

```bash
virsh -c qemu:///system console ubuntu-tf
```

Pour quitter la console :

```text
Ctrl + ]
```

---

### Voir les informations détaillées d’une VM

```bash
virsh -c qemu:///system dominfo ubuntu-tf
virsh -c qemu:///system dumpxml ubuntu-tf
```

---

### Voir les disques d’une VM

```bash
virsh -c qemu:///system domblklist ubuntu-tf
```

---

### Lister les volumes dans un pool

```bash
virsh -c qemu:///system vol-list default
```

---

### Lister les réseaux libvirt

```bash
virsh -c qemu:///system net-list --all
```

---

### Voir la configuration d’un réseau

```bash
virsh -c qemu:///system net-dumpxml default
```

---

## 3) Commandes SSH et interaction avec la VM

### Connexion SSH à la VM

```bash
ssh -i ../key/terraform-key ubuntu@IP_DE_LA_VM
```

---

### Copier un fichier vers la VM

```bash
scp -i ../key/terraform-key fichier.txt ubuntu@IP_DE_LA_VM:/home/ubuntu/
```

---

### Récupérer un fichier depuis la VM

```bash
scp -i ../key/terraform-key ubuntu@IP_DE_LA_VM:/home/ubuntu/log.txt .
```

---

### Exécuter une commande à distance

```bash
ssh -i ../key/terraform-key ubuntu@IP_DE_LA_VM "uptime"
```


## 4) Cheat-sheet minimal

```bash
# Terraform
terraform plan
terraform apply
terraform destroy

# Libvirt
virsh -c qemu:///system list --all
virsh -c qemu:///system start ubuntu-tf
virsh -c qemu:///system shutdown ubuntu-tf
virsh -c qemu:///system domifaddr ubuntu-tf

# SSH
ssh -i ../key/terraform-key ubuntu@IP_DE_LA_VM
```