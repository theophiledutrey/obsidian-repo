![[IMG-20251029144023000.png]]

## 🔹 Informations générales

- **Fonction** : `main`
- **Convention d’appel** : System V AMD64 (`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` pour les 6 premiers arguments)
- **Prologue / Épilogue** : gestion classique de la pile
- **Compilateur** : `gcc` (utilise `___isoc99_scanf`)
- **Fonctionnalité** : demande un nom et un âge à l’utilisateur, puis les affiche

---

## 🔹 Variables locales

| Nom | Offset | Type | Rôle |
|------|---------|--------|------|
| `var_40` | `rbp-0x40` | `char[64]` | Buffer pour stocker le nom |
| `var_44` | `rbp-0x44` | `int` | Variable pour l’âge |

> La pile réserve `0x50 = 80` octets pour ces variables locales.

---

## 🔹 Structure du programme

### 1. Prologue
```asm
push rbp
mov rbp, rsp
sub rsp, 50h
```
➡️ Sauvegarde de l’ancien pointeur de base (`rbp`) et allocation de 80 octets sur la pile.

---

### 2. Affichage du prompt "Entrez votre nom :"
```asm
lea rax, format     ; "Entrez votre nom : "
mov rdi, rax        ; 1er argument
mov eax, 0
call _printf
```
➡️ `printf("Entrez votre nom :");`

---

### 3. Lecture du nom
```asm
lea rax, [rbp+var_40] ; adresse du buffer
mov rsi, rax          ; 2e argument = &buffer
lea rax, a49s         ; "%49s"
mov rdi, rax          ; 1er argument = format
mov eax, 0
call ___isoc99_scanf
```
➡️ `scanf("%49s", nom);`  
Protège contre les dépassements de buffer (lecture limitée à 49 caractères).

---

### 4. Affichage du prompt de l’âge
```asm
lea rax, aEntrezVotre ; "Entrez votre "
mov rdi, rax
mov eax, 0
call _printf
```
➡️ `printf("Entrez votre âge :");` (la chaîne semble incomplète dans IDA).

---

### 5. Lecture de l’âge
```asm
lea rax, [rbp+var_44] ; &age
mov rsi, rax
lea rax, unk_2036     ; probablement "%d"
mov rdi, rax
mov eax, 0
call ___isoc99_scanf
```
➡️ `scanf("%d", &age);`

---

### 6. Affichage du message final
```asm
mov edx, [rbp+var_44]      ; 3e arg = age
lea rax, [rbp+var_40]      ; 2e arg = nom
mov rsi, rax
lea rax, aBonjourSVousAv   ; "Bonjour %s, vous avez %d ans !\n"
mov rdi, rax
mov eax, 0
call _printf
```
➡️ `printf("Bonjour %s, vous avez %d ans !\n", nom, age);`

---

## 🔹 Détails techniques

| Instruction | Description |
|-------------|--------------|
| `lea` | *Load Effective Address* — charge une adresse mémoire dans un registre sans la déréférencer. |
| `mov` | Copie une valeur d’un registre ou d’une adresse vers un autre registre ou mémoire. |
| `push` / `pop` | Sauvegarde/restaure un registre sur la pile. |
| `sub rsp, 50h` | Réserve de l’espace sur la pile pour les variables locales. |
| `call` | Appel de fonction — pousse l’adresse de retour sur la pile. |
| `rbp`, `rsp` | `rbp` = pointeur de base du cadre courant, `rsp` = pointeur de pile. |
| `eax`, `edx`, `rsi`, `rdi`, `rax` | Registres utilisés pour le passage d’arguments et le retour de fonctions. |

---

## 🔹 Reconstruction C

```c
#include <stdio.h>

int main(void) {
    char nom[64];
    int age;

    printf("Entrez votre nom : ");
    scanf("%49s", nom);

    printf("Entrez votre âge : ");
    scanf("%d", &age);

    printf("Bonjour %s, vous avez %d ans !\n", nom, age);
    return 0;
}
```

---

## 🔹 Points importants

- ✅ **Usage sécurisé de scanf** avec `%49s` (limite la taille de lecture).  
- ⚠️ `%s` s’arrête au premier espace (pas de prénoms composés).  
- ⚠️ Vérification des valeurs de retour `scanf` absente.  
- ℹ️ `mov eax, 0` avant les appels variadiques (`printf`, `scanf`) est exigé par la convention d’appel SysV.  



![[IMG-20251029150758523.png]]

Les **registres** sont de petites zones de mémoire **ultra-rapides** intégrées directement dans le processeur.  
Ils servent à stocker temporairement des données pendant l’exécution des instructions machine (valeurs, adresses, résultats intermédiaires…).

Sur une architecture **x86 32 bits**, les registres généraux ont une largeur de **32 bits** et sont nommés ainsi :

|Nom 32 bits|Nom 16 bits|8 bits hauts|8 bits bas|Description|
|---|---|---|---|---|
|**EAX**|AX|AH|AL|Registre d’accumulateur — utilisé pour les opérations arithmétiques et logiques|
|**EBX**|BX|BH|BL|Registre de base — souvent utilisé pour contenir des adresses mémoire|
|**ECX**|CX|CH|CL|Registre compteur — souvent utilisé dans les boucles et les décalages|
|**EDX**|DX|DH|DL|Registre de données — utilisé pour les opérations d’E/S et multiplications|
|**ESI**|SI|—|—|Registre source d’index (Source Index), souvent pour le traitement de chaînes|
|**EDI**|DI|—|—|Registre destination d’index (Destination Index)|
|**ESP**|SP|—|—|**Stack Pointer** — pointeur de pile (adresse du sommet de la pile)|
|**EBP**|BP|—|—|**Base Pointer** — pointeur de base du cadre de pile courant|

---

## 🧩 Structure hiérarchique des registres

Chaque registre 32 bits (EAX, EBX, ECX, EDX) peut être découpé en plus petites parties :

- **16 bits de poids faible** : accessibles via le nom sans le “E” → ex : `AX`
    
- **8 bits de poids faible** : `AL` (Low)
    
- **8 bits de poids fort** : `AH` (High)
    

---

## Exemple concret

Supposons :

`mov eax, 0x12345678`

Alors :

- `EAX = 0x12345678`
    
- `AX = 0x5678`
    
- `AH = 0x56`
    
- `AL = 0x78`
    

---

## 🧭 Registres spéciaux (ESP / EBP)

- **ESP (Stack Pointer)** : pointe sur le haut de la pile (dernier élément poussé).  
    → utilisé dans les fonctions pour empiler les variables et les adresses de retour.
    
- **EBP (Base Pointer)** : marque la base du cadre de pile de la fonction courante.  
    → permet d’accéder aux variables locales et arguments via des offsets (`[ebp-4]`, `[ebp+8]`, etc.).


## **ASSEMBLY LANGUAGE (INTEL X86)**

|Instruction|Effet|
|---|---|
|`MOV EAX, 1`|EAX = 1|
|`ADD EBX, 5`|EBX = EBX + 5|
|`SUB EBX, 2`|EBX = EBX - 2|
|`AND ECX, 0`|ECX = ECX & 0 → ECX = 0|
|`XOR EDX, 4`|EDX = EDX ⊕ 4 (opération XOR binaire)|
|`INC ECX`|ECX = ECX + 1|

Ensuite, deux instructions supplémentaires en rouge :

- `lea eax, [ebx+8]`
    
- `mov eax, [ebx]`
    

---

## 🔍 **Explication ligne par ligne**

### 1. `MOV EAX, 1`

- **MOV** copie une valeur.
    
- Ici on met la valeur immédiate `1` dans le registre `EAX`.
    
- 👉 Résultat : `EAX = 1`.
    

### 2. `ADD EBX, 5`

- **ADD** additionne une valeur au contenu du registre.
    
- 👉 `EBX = EBX + 5`.
    

### 3. `SUB EBX, 2`

- **SUB** soustrait la valeur donnée du registre.
    
- 👉 `EBX = EBX - 2`.
    

### 4. `AND ECX, 0`

- **AND** fait une opération ET binaire entre `ECX` et `0`.
    
- Tout bit ET 0 = 0 → donc `ECX` devient `0`.
    

### 5. `XOR EDX, 4`

- **XOR** (OU exclusif) compare chaque bit :
    
    - 0 ⊕ 0 = 0
        
    - 1 ⊕ 0 = 1
        
    - 0 ⊕ 1 = 1
        
    - 1 ⊕ 1 = 0
        
- C’est souvent utilisé pour :
    
    - inverser certains bits,
        
    - ou remettre un registre à zéro si on fait `XOR EAX, EAX`.
        

### 6. `INC ECX`

- **INC** (increment) augmente de 1.
    
- 👉 `ECX = ECX + 1`.
    

---
### `lea eax, [ebx+8]`

- **LEA** = _Load Effective Address_ (charge une adresse calculée).
    
- Elle **ne lit pas la mémoire**, elle calcule simplement une adresse.
    
- Ici, `EAX = EBX + 8`.
    
- ⚙️ Très utile pour faire des calculs d’adresse ou d’offset rapidement sans affecter les flags.
    

### `mov eax, [ebx]`

- **MOV** lit la valeur contenue à l’adresse pointée par `EBX`.
    
- Les crochets `[ ]` signifient _“contenu à l’adresse de”_.
    
- 👉 `EAX = *(uint32_t*)EBX` (en C).
    

---

## 🧩 **Résumé visuel**

|Type d’instruction|Exemple|Effet principal|
|---|---|---|
|Affectation|`MOV EAX, 1`|Met une valeur dans un registre|
|Addition/Soustraction|`ADD`, `SUB`|Opérations arithmétiques|
|Logique binaire|`AND`, `XOR`|Manipulation de bits|
|Incrémentation|`INC`|+1|
|Adresse mémoire|`LEA`, `MOV [ ]`|Calcul ou accès mémoire|