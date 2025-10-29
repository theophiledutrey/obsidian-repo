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

---

**Auteur :** ChatGPT (analyse du code IDA pour Obsidian)  
**Date :** 2025-10-29