Commande Pentest:

```bash
ffuf -w wordlist -u url/FUZZ -of html -o ton-fichier-de-sortie.html -t 4 -p 0.1 -H "User-Agent: XMCO-TDUT" -c -r
```

Pour raccourcir une liste en retirant N ligne:

```bash
tail -n +N wordlist.txt > wordlist_resume.txt
```

```bash
ffuf -u https://<url>/index.php?r=FUZZ \ -w /usr/share/wordlists/dirb/common.txt \ -fc 404
```



