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

## Instructions

## 1) Déplacement de données (Data movement)

|Instruction|Syntaxe|Description / Effet|Flags|
|---|---|---|---|
|`MOV`|`MOV r, r/m/imm`|Copie valeur → registre/mémoire (`MOV eax, 1`, `MOV eax, [ebx]`). Ne modifie pas (normalement) les flags.|—|
|`MOVZX`|`MOVZX r, r/m`|Move with zero-extend : copie et étend en zéro (ex : byte→word).|—|
|`MOVSX`|`MOVSX r, r/m`|Move with sign-extend : étend le signe (signed).|—|
|`LEA`|`LEA r, [base + index*scale + disp]`|Charge l'**adresse effective** calculée dans `r`. N’accède pas à la mémoire. (ex : `lea eax, [ebx+8]` → `eax=ebx+8`).|—|
|`XCHG`|`XCHG r, r/m`|Échange deux opérandes.|—|
|`PUSH`|`PUSH r/m/imm`|Empile sur la pile (décrémente `ESP/RSP`, écrit mémoire).|—|
|`POP`|`POP r/m`|Dépile (lit mémoire, incrémente `ESP/RSP`).|—|
|`MOVSB/MOVSW/MOVSD/MOVSQ`|`MOVSx`|Copie blocs mémoire source→dest (utilisé avec `ESI`/`EDI` et `REP`).|—|

---

## 2) Arithmétique de base

|Instruction|Syntaxe|Description / Effet|Flags|
|---|---|---|---|
|`ADD`|`ADD r/m, r/imm`|Additionne, stocke dans destination.|ZF, SF, CF, OF|
|`SUB`|`SUB r/m, r/imm`|Soustrait.|ZF, SF, CF, OF|
|`INC`|`INC r/m`|+1 (n’altère pas CF sur x86|64, mais modifie OV/ZF/SF).|
|`DEC`|`DEC r/m`|-1.|ZF, SF, OF (pas CF)|
|`NEG`|`NEG r/m`|Change signe (0 - x).|ZF, SF, CF, OF|
|`IMUL`|`IMUL r, r/m/imm` / mul variants|Multiplication signée (différentes formes). Résultat wide selon variante.|OF, CF (selon variante)|
|`MUL`|`MUL r/m`|Multiplication non signée (unsigned).|OF, CF|
|`IDIV` / `DIV`|`IDIV r/m` / `DIV r/m`|Division signée/unsigned (opérande implicite en eax:edx).|Exceptions CPU si div par 0 ou overflow|
|`ADC`|`ADC dst, src`|Add with carry (utilise CF).|ZF,SF,CF,OF|
|`SBB`|`SBB dst, src`|Sub with borrow (utilise CF).|ZF,SF,CF,OF|

---

## 3) Logique binaire & bitwise

|Instruction|Syntaxe|Description / Effet|Flags|
|---|---|---|---|
|`AND`|`AND dst, src`|ET binaire.|ZF, SF, CF=0, OF=0|
|`OR`|`OR dst, src`|OU binaire.|ZF, SF, CF=0, OF=0|
|`XOR`|`XOR dst, src`|OU exclusif. Souvent `XOR eax,eax` met 0 et clear flags.|ZF, SF, CF=0, OF=0|
|`NOT`|`NOT r/m`|Bitwise NOT (complément).|—|
|`TEST`|`TEST a, b`|AND sans stocker, met flags (utile pour conditions).|ZF, SF, PF|

---

## 4) Décalages & rotations (bit shifts)

|Instruction|Syntaxe|Description|Flags|
|---|---|---|---|
|`SHL` / `SAL`|`SHL dst, count`|Shift left (multiplication par 2^n).|CF, OF, ZF, SF|
|`SHR`|`SHR dst, count`|Logical shift right (insère 0 à gauche).|CF, OF, ZF, SF|
|`SAR`|`SAR dst, count`|Arithmetic shift right (préserve signe).|CF, OF, ZF, SF|
|`ROL` / `ROR`|`ROL dst, count`|Rotate left / right (bits circulent).|CF (et OF parfois)|

---

## 5) Comparaison & branchement conditionnel

|Instruction|Syntaxe|Description / Effet|Flags|
|---|---|---|---|
|`CMP`|`CMP a, b`|Compare (a - b) : met les flags, n’écrit pas le résultat.|ZF, SF, CF, OF|
|`TEST`|`TEST a, b`|Bitwise AND -> flags.|ZF, SF, PF|
|`JMP`|`JMP label`|Jump inconditionnel (near/short/indirect).|—|
|`JE / JZ`|`JE label`|Jump if equal / zero (`ZF=1`).|dépend des flags|
|`JNE / JNZ`|`JNE label`|Jump if not equal (`ZF=0`).|—|
|`JG / JNLE`|`JG label`|Jump if greater (signed).|—|
|`JGE`|`JGE label`|Jump if greater or equal (signed).|—|
|`JL / JNGE`|`JL label`|Jump if less (signed).|—|
|`JA / JNBE`|`JA label`|Jump if above (unsigned, CF=0 & ZF=0).|—|
|`JB / JC`|`JB label`|Jump if below (unsigned, CF=1).|—|
|`SETcc`|`SETZ/SETNZ/SETG...`|Stocke 0/1 dans un octet selon condition (ex : `SETZ al`).|—|

---

## 6) Appels / retours / gestion de pile (control transfer)

|Instruction|Syntaxe|Description / Effet|Flags|
|---|---|---|---|
|`CALL`|`CALL label` / `CALL r/m`|Appel de fonction : empile adresse de retour (EIP/RIP) puis jump.|—|
|`RET`|`RET` / `RET imm`|Retour d’un appel : dépile adresse de retour dans EIP/RIP. `RET imm` ajuste la pile.|—|
|`ENTER` / `LEAVE`|création/démontage de frame locale (`enter 16,0` / `leave`)|Facilite frames de fonctions (EBP/ESP).|—|
|`INT`|`INT 0x80` / `INT n`|Interruption logicielle (syscalls en mode legacy).|—|
|`SYSCALL` / `SYSENTER`|appels système rapides (64-bit / fast)|Utilisé pour appels kernel modernes.|—|

---

## 7) Instructions de pile rapides (32-bit / 64-bit)

|Instruction|Syntaxe|Remarques|
|---|---|---|
|`PUSHAD` / `POPAD`|32-bit only|Sauvegarde/restaure tous registres généraux (legacy).|
|`PUSHF` / `POPF`|Empile/dépile flags|Utile pour sauver flags.|

---

## 8) Instructions floating-point / SIMD (FPU / SSE / AVX) — essentielles à connaître

|Instruction|Syntaxe|Description|
|---|---|---|
|`FPU` (ex: `FLD`, `FSTP`)|instructions x87|Ancienne FPU stack (floating point).|
|`MOVSD`|`MOVSD xmm, xmm/m64`|Move scalar double (SSE2) — déplacer un double flottant.|
|`MOVSS`|`MOVSS xmm, xmm/m32`|Move scalar single float.|
|`MOVDQA` / `MOVDQU`|move SIMD aligned/unaligned|Pour vecteurs 128-bit.|
|`ADDSD`, `SUBSD`, `MULSD`, `DIVSD`|opérations floating SSE|Opérations en virgule flottante sur xmm.|

> Dans ton extrait on voit `movsd` : c’est **MOV scalar double** (SSE2) — copie un `double` en mémoire/registre XMM.

---

## 9) Instructions de conversion / extension

|Instruction|Syntaxe|Description|
|---|---|---|
|`CVTSI2SD` / `CVTSI2SS`|convert int → double/float|Conversion entiers → flottants.|
|`CVTSD2SI`|convert double → int|etc.|

---

## 10) Instructions système / utilitaires

| Instruction | Syntaxe | Remarques                                     |
| ----------- | ------- | --------------------------------------------- |
| `NOP`       | `NOP`   | No operation — parfois alignement ou timing.  |
| `HLT`       | `HLT`   | Arrête le CPU jusqu’à interruption.           |
| `CPUID`     | `CPUID` | Récupère infos processeur (vendor, features). |
| `RDTSC`     | `RDTSC` | Lire time-stamp counter (cycle counter).      |