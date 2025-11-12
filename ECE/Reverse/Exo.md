| Valeur | Adresse |
| :----: | :-----: |
|  0x41  | 0x1000  |
|  0x42  | 0x1004  |
|  0x43  | 0x1008  |
|  0x44  | 0x100C  |
|  0x45  | 0x1010  |
|  0x46  | 0x1014  |

**ecx = 0x100C**

mov edx, ecx              --> edx = 0x100C
mov eax, [edx]           --> eax = 0x44
lea ecx, [ecx + 4]       --> ecx = 0x1010
mov ebx, [ecx]           --> ebx = 0x45
mov eax, ecx             --> eax = 0x1010
mov eax, [ebx]           --> eax = ????
