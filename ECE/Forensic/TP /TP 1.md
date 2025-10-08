
![[IMG-20251008111131218.pdf]]


## Étapes de montage

### 1. Monter l’E01 avec ewfmount
```bash
sudo ewfmount TP_USB.E01 mnt_ewf
```
- `ewfmount` lit le fichier `.E01` (format EnCase) et expose un **fichier brut virtuel** dans `mnt_ewf/ewf1`.
- Ce fichier représente le disque entier de la clé.

### 2. Associer le fichier brut à un loop device
```bash
sudo losetup -f --show mnt_ewf/ewf1
```
- Crée un périphérique bloc `/dev/loopX` (exemple : `/dev/loop5`).
- La commande affiche le loop device créé.

### 3. Vérifier la table de partitions
```bash
sudo fdisk -l /dev/loop5
```
- Permet de voir si le disque brut contient une table de partitions (MBR/GPT).

### 4a. Si le disque contient des partitions → mapper avec kpartx
```bash
sudo kpartx -av /dev/loop5
# crée /dev/mapper/loop5p1, /dev/mapper/loop5p2, ...
sudo mount -o ro /dev/mapper/loop5p1 /mnt/usb2
```
- Monte la première partition en **lecture seule**.

### 4b. Si le disque contient directement un système de fichiers
```bash
sudo mkdir -p /mnt/usb2
sudo mount -o ro /dev/loop5 /mnt/usb2
```
- Monte directement le loop device.

---

## Nettoyage (démontage propre)

```bash
sudo umount /mnt/usb2              # démonte le point de montage
sudo kpartx -dv /dev/loop5         # supprime les devices /dev/mapper/loop5p*
sudo losetup -d /dev/loop5         # détache le loop device
sudo fusermount -u mnt_ewf         # démonte ewfmount (ou: sudo umount mnt_ewf)
```

---

## 1) Extraire les tags GPS avec ExifTool

Si tu as déjà une liste d’images (`workdir/image_list.txt`) :
```bash
exiftool -csv -gpslatitude -gpslongitude -gpsaltitude -DateTimeOriginal -Model -Make -Filename -@ workdir/image_list.txt > workdir/gps_report.csv
```
Ou pour une image précise :
```bash
exiftool -gps:all -DateTimeOriginal -Model -Make -a -G1 -s /mnt/usb2/reperage.jpg > workdir/reperage_exif.txt
```

### Tableau extrait

| SourceFile                           | GPSLatitude         | GPSLongitude       | DateTimeOriginal    | Model    | Make              | FileName                   |
| ------------------------------------ | ------------------- | ------------------ | ------------------- | -------- | ----------------- | -------------------------- |
| /mnt/usb2/_museum_flat_visual_HR.jpg |                     |                    | 2018:06:06 20:10:57 | NIKON D5 | NIKON CORPORATION | _museum_flat_visual_HR.jpg |
| /mnt/usb2/reperage.jpg               | 52 deg 21' 29.52" N | 4 deg 52' 51.67" E | 2023:04:01 12:18:00 |          |                   | reperage.jpg               |
| /mnt/usb2/Van_Gogh.jpg               |                     |                    |                     |          |                   | Van_Gogh.jpg               |

---

## Conversion des coordonnées (reperage.jpg)

- Latitude : `52 deg 21' 29.52" N` → **52.358200**
- Longitude : `4 deg 52' 51.67" E` → **4.881019**


Lien OpenStreetMap :  
[https://www.openstreetmap.org/?mlat=52.358200&mlon=4.881019#map=18/52.35820/4.88102](https://www.openstreetmap.org/?mlat=52.358200&mlon=4.881019#map=18/52.35820/4.88102)

## Retrouver l'arme avec PhotoREC
![[IMG-20251008111131262.png]]

![[IMG-20251008111131338.png]]

![[IMG-20251008111131648.png]]

![[IMG-20251008111131817.png]]

![[IMG-20251008111131886.png]]

![[IMG-20251008111131988.png]]

![[IMG-20251008111132065.png]]

![[IMG-20251008111132501.png]]

