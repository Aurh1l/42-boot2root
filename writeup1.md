# Enumeration

- `nmap -T4 --top-ports 1000 192.168.56.8`
```
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
143/tcp open  imap
443/tcp open  https
993/tcp open  imaps
```

We can see an HTTTP(S) server running. Let's check it out !\
It's a simple website with nothing in particular, we must dig into it.


**http://192.168.56.8/admin** returns 404 but we get the version of the webserver, *Apache/2.2.22*, it may be interesting
later.

Let's fuzz the website.

- `ffuf -c -w /opt/secliosts/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.56.8/FUZZ`

```
forum                   [Status: 403, Size: 285, Words: 21, Lines: 11, Duration: 0ms]
fonts                   [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 0ms]
server-status           [Status: 403, Size: 293, Words: 21, Lines: 11, Duration: 0ms]
```

We found some things interesting but we cannot access it since it returns the code **403**. Earlier we saw that there is
also an **https** server, we should try it.

- `ffuf -c -w /opt/secliosts/Discovery/Web-Content/directory-list-2.3-medium.txt -u https://192.168.56.8/FUZZ`

```
forum                   [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 0ms]
webmail                 [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 0ms]
phpmyadmin              [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 0ms]
server-status           [Status: 403, Size: 294, Words: 21, Lines: 11, Duration: 0ms]
```

Bingo ! We cannot log into the phpmyadmin, defaults credentials don't work. Let's check the forum.

The main page is **https://192.168.56.8/forum/index.php?mode=index**, let's try to fuzz the *mode* parameter.

```
search                  [Status: 200, Size: 3001, Words: 183, Lines: 64, Duration: 22ms]
contact                 [Status: 200, Size: 3418, Words: 209, Lines: 71, Duration: 26ms]
rss                     [Status: 200, Size: 63240, Words: 7461, Lines: 648, Duration: 20ms]
login                   [Status: 200, Size: 3270, Words: 208, Lines: 69, Duration: 26ms]
register                [Status: 200, Size: 2538, Words: 161, Lines: 59, Duration: 33ms]
page                    [Status: 200, Size: 2517, Words: 155, Lines: 59, Duration: 30ms]
0                       [Status: 200, Size: 4935, Words: 310, Lines: 81, Duration: 33ms]
user                    [Status: 200, Size: 5065, Words: 236, Lines: 139, Duration: 41ms]
admin                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 36ms]
entry                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 38ms]
thread                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 34ms]
posting                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 142ms]
avatar                  [Status: 200, Size: 2099, Words: 265, Lines: 51, Duration: 374ms]
disabled                [Status: 200, Size: 2530, Words: 157, Lines: 59, Duration: 39ms]
```

There is a **Probleme login** post on the forum that might be interesting.

- **Oct 5 15:03:55 BornToSecHackMe sudo: root : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/sbin/service vsftpd restart**

An ftp server might be running and a user *admin* exists.

In all request to the forum: **<meta name="generator" content="my little forum 2.3.4" />**
