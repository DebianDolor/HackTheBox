# 1. Enumeration

- Just as usual, we start off with the nmap scan:

![img.png](img/img.png)

-  We will start off with enumeration of the port 21, since the Nmap shows that it allows anonymous login:

![img_1.png](img/img_1.png)

- When we will try to unzip it, the compressed archive asks us for a password. We will crack the password with `john`:

```
zip2john backup.zip > hashes
john hashes
john --show hashes
```

![img_2.png](img/img_2.png)

- Now, we can extract the files:

![img_3.png](img/img_3.png)

- We will read `index.php` first:

```
session_start();
if(isset($_POST['username']) && isset($_POST['password'])) {
if($_POST['username'] === 'admin' && md5($_POST['password']) ===
"2cb42f8734ea607eefed3b70af13bbd3") {
$_SESSION['login'] = "true";
header("Location: dashboard.php");
```

- Looks like the password is md5 hashed, but we can easily break it. This left us with `admin:qwerty789`

- Visit the website and login using the above username and password:

![img_4.png](img/img_4.png)

- Nothing much, but the `search` parameter is vulnerable to SQL Injection:

![img_5.png](img/img_5.png)

- Now we will attempt to get an OS Shell so as to create a reverse shell back to our netcat listener:

![img_6.png](img/img_6.png)
![img_7.png](img/img_7.png)

- The user flag could be found in `/var/lib/postgresql/`

# 2. Privilege Escalation

- We are user `postgres`, but we don't know the password for it, which means we cannot check our sudo privileges.

- Therefore, we will try to find the password in the /var/www/html folder, since the machine uses both PHP & SQL,
meaning that there should be credentials in clear text. In the `dashboard.php`, we found the following:

![img_8.png](img/img_8.png)

- Now that we know the username and password, we can connect to the target machine with SSH to get a more stable shell.

- Let's check our privileges:

![img_9.png](img/img_9.png)

- So we have sudo privileges to edit the `pg_hba.conf` file using `vi` by running sudo `/bin/vi
/etc/postgresql/11/main/pg_hba.conf`. We will go to GTFOBins to see if we can abuse this privilege:
https://gtfobins.github.io/gtfobins/vi/#sudo

![img_10.png](img/img_10.png)

- Let's try to execute it:

![img_11.png](img/img_11.png)

- We are unable to execute the following command because `sudo` is restricted to only `/bin/vi
/etc/postgresql/11/main/pg_hba.conf`.

- But there's also an alternative way according to GTFOBins:

```
vi
:set shell=/bin/sh
:shell
```

- So we will perform that as well:

```
postgres@vaccine:~$ sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

- We managed to open `vi` as the superuser, which has root privileges:

![img_12.png](img/img_12.png)

- Now we will press the : button to set the instructions inside `vi`: `:set shell=/bin/sh`

![img_13.png](img/img_13.png)

- Next, we will open up the same instruction interface & type the following: `:shell`

![img_14.png](img/img_14.png)

- After we execute the instructions, we will see the following:

![img_15.png](img/img_15.png)

- The root flag can be obtained in the root folder.