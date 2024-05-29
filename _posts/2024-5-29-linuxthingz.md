---
title: "Linux Cheatsheet"
date: 2024-05-25 19:42:00
categories: [notes,cheatsheet]
tags: [linux,cheatsheet]
---

`cat /etc/mtab` will show list of mounted drives

`grep -i 'chuks" chuks.txt`   will show output with in noncase sensiteve form in specified doc

`grep -V "^ chuks"`   will NOT look for anything that starts with chuks
  
**Man Pages**
To show all man pages on an issue do `man-k ‘topic’`
Or apropos

**Fuser** 

`fuser -m /secretstuff` —shows process name been ed by /secretstuff

`fuser -km /secretstuff` —kills process being accessed by /secrestuff

`fuser -v /opt/cjhukky` shows verbosely what is accessing the file cjhukky

**sync for flushing filesystem**

sync; echo 1 > /proc/sys/vm/drop_caches —- this will clear cache and buffer in memory —echo options are 1,2 and 3 -3 will clear all pagecache, inode,and dentries..

`mount -o remount, rw`  - this will forcefully remount a readonly filesystem

ps -ef all processes or ps -aux
ps -ef f will list threaded process with dependencies

ntp -q

**RSYNC**

rsync -av dir1/ dir2 The -a option is a combination flag. { for local systems within directories}

it stands for “archive” and syncs recursively and preserves symbolic links, special and device files, modification times, group, owner, and permissions.
Note that dir1/ would place content of dir1/into dir2 without the trailing / in dir1/ like rsync -a dir1 dir2 it will move directory and content to dir2 looking like this
dir2/dir1/ {}files}

rsync -av ~/dir1 username@remote_host:destination_directory —-in a PUSH fashion pushing a local directory to a remote destination

or pulling from a remote location into a local directory we do rsync -av username@remote_host:/home/username/dir1 place_to_sync_on_local_machine

options : z compress

**TAR CREATION**

tar -cvf tecmint-14-09-12.tar /home/tecmint/ —creates without gzip or bzip compression
adding z will comppress with gzip ==adding J compress with bzip which is better compression, smaller files but takes up more times ( make sure file name ends with .bz2)

**UNTARRING**
tar -xvf public_html-14-09-12.tar — to untar file in current directory option -C to **change directory…then path /whatever/whatever/w
option t —lists content of tarball

—- to untar single file format ==tar =xvf tarball.tar filetobuntarred for multiple —>>>>tar -xvf tecmint-14-09-12.tar “file 1” “file 2”

to add to an existing
v
Find
rsync

find /root/chukky -name “{*” | xargs rm this will find file that have { as a start and remove it.

OR
find / -size +100M -exec rm -rf {} \; ( To find all 100MB files and delete them using one single command.)

find / -mtime 50 ( **note m = modified time is a 24hours [peirod , so mtime 50== modified 50 DAYS AGO])
find / -atime 50 a= acces 50 days ago
find / -mtime +5 –mtime -100 ( for files modified more than 5-days but less than 100)

find / -cmin -60 ( files that have been changed 60min ( or 1 hour))
find /-mmin -60 files modified in d last hour

find / -size +50M -size -100M (To find all the files which are greater than 50MB and less than 100MB.)
find / -user chuks -exec cp -af {} /tmp/chukstemp/ \;
<< This will find all files and folders owned by user chuks and copy them to /tmp/chukstemp :
/exec = executes commands
{ } == puts the results from find command
\; == end d line

**LSOF**

Lsof -c { program} ( list open files) “c” program option
e.g lsof -c ssh
lsof -iI shows node and their connections
lsof -i:portnumber ( to see connection status on port)

MYSQL ——>> mtop to find top live queries that may be hugging a database

MYSQL (check out http://dev.mysql.com/doc)
login == mysql -u root -p -h

show databases ——- to show current databases
create user == CREATE USER ‘username’@’localhost’ IDENTIFIED BY ‘password’;
to showsh mysql users == SELECT User,Host FROM mysql.user;

TO SHOW HASHED PASSWORD
mysql> select user,host,password from mysql.user;
+————-+———————————————+—————————————————————-+
| user | host | password |
+————-+———————————————+—————————————————————-+
| root | localhost | D6D2D332378F65F060076BA885C1F513706C1452 |
| root | pandoramaster-01.localdomain | |
| root | 127.0.0.1 | |
| | localhost | |
| | pandoramaster-01.localdomain | |
| pandora | localhost | E035D2FEB2ECCFB51DA13B6D2588E041B0196D08 |

For server side help ——- help contents
then help listed e.g help administration

GRANT READONLY ACCESS on databases
mysql> GRANT SELECT on fleetman.* to ‘muirs’@’%’; or ‘muirs’@’ipaddress or localhost’

TO REVOKE PRIVILEDGE
mysql> mysql> REVOKE SELECT ON NAME OF DATABSE. FROM ‘pitchfordp’@’%’;
REVOKE SELECT ON DNA. FROM ‘pitchfordp’@’%’;

To show permissions == SHOW GRANTS FOR ‘nomadsda’@’%’;

To showTABLES IN A DATABSE —-
use (name of database;)
show tables;

Get database size
mysql> select table_schema “database name”,Round(sum(data_length + index_length)/1024/1024,1) “Database Size in MB” from information_schema.TABLES GROUP BY table_schema;

Count number of databases excluding mysql and informaion_schema

MariaDB [information_schema]> select SCHEMA_NAME,SQL_PATH from SCHEMATA;

+——————————+—————+
| SCHEMA_NAME | SQL_PATH |
+——————————+—————+
| information_schema | NULL |
| FOOD | NULL |
| chukEEE | NULL |
| mysql | NULL |
| performance_schema | NULL |
| test | NULL |
| wordpress | NULL |
+——————————+—————+

select count(*) from information_schema.SCHEMATA where schema_name not in
(‘mysql’,’information_schema’);

**MYSQLDUMP**

mysqldump u root -p —all-databases >/root/chuks.sql { to make a backup} best way is to backup individual databases

mysql - u root -p </root/chuks.sql will REStore aLL databases to that.

to delete database use drop command then —create the empty database then restore using mysql -u root -p ( database name) < ( databasename.sql)

The most common options for FLUSH command are:

PRIVILEGES
TABLES
HOSTS
LOGS

Flushes cleares cahce of whatever and implements immediately instead or restarting mysqld service or the server.

CHATTR and LSATTR

CHATTRR to change file /Directory security attributes. options a = append ONLY canot overite ; i= imuttability cannot be added to nor deleted -R recursive
EXAMPLE= chattr +i iamboss
[root@orlu Babaooo]# lsattr iamboss
——i————e- iamboss

remove by [root@orlu Babaooo]# chattr -i iamboss
[root@orlu Babaooo]# lsattr iamboss
——————-e- iamboss

[root@orlu Babaooo]# lsattr
——————-e- ./test
——ia———-e- ./iamboss _>>>>>> with the ‘a’ flag and ‘i” there will be deny and nothing can be added nor deleted

chattr -R +i Babaooo/
[root@orlu ~]# lsattr Babaooo/
——i————e- Babaooo/test
——i———-e- Babaooo/iamboss
——i————e- Babaooo/testing
——i————e- Babaooo/this
——i————e- Babaooo/yo

This recurrsviely makes all files in Baba000/ directory immutable .

ACL ( can be performed per user, grop via right mask ans users not in d usergroup of file)

Note not all filesystems ddon’t support it . In RHEL 7 ext4 and xfs support it
format setfacl -m (rules) (files)
setfacl -Rm d:u:foo:rwX /test

were R=recursive d = default acl from mask u = users m = to add or modify acl of a file or directory
TO reset ACL to default use setfacl -Rb /

were b is to erase acl info adn restore default and R is recursive
-d ( set default acl info only on folders) e.g setfacl -d u:chuks:rw /rootfile.txt
or setfacl-m d:u:chuks:rw /folder
or for defaults in files = setfacl -m d:u::r afolder/ so any files recreated inside afolder will be only readonly
-k (erase default acl info)
-b e.g setfacl -b rootfile.txt will remove acl

to add groups e.g setfacl -m g:marketing:rw,g:advertising:rw rootfile.txt

useradd -m -s /bin/bash -c “chuks okonkwo”

IPTABLES
iptables -L -t nat to list nat forwarding rules..
iptables -L -t nat -A PREROUTING

snmpd to monitor process with prtg
goto /etc/snmpd/snmpd.conf add process for example to monitor dhcpd on a server in the file ( /etc/snmpd/snmpd.conf) add proc dhcpd 1,1

XXXXXXX

taskset -pc -1 (pid)

To find available ip address to use
—- will scan for available ports in the 172.16.247-0
USE nmap -sP 172.16.247.0/24 ( will not tell the total hosts)or
nmap -sP 172.16.247.1-255 = this will list the total hosts upthat is up and the rest numbers will be the free ones to use.
e.g

Nmap scan report for 172.16.247.217
Host is up (0.0066s latency).
Nmap scan report for 172.16.247.218
Host is up (0.0066s latency).
Nmap scan report for 172.16.247.233
Host is up (0.0090s latency).
Nmap done: 255 IP addresses (29 hosts up) scanned in 3.26 seconds

logger options for sending messages.

mount vbox guesttools or xenserver tools

after enabling in citrix or vbox = we mount the cd ..find th ename using fdisk -l to see lists.>> mount e.g mount /dev/xvdd /mnt >> cd into mount look for folder
and enter then run install script lik ./install.sh

PATCHING

diff -Naur /usr/src/openvpn-2.3.2 /usr/src/openvpn-2.3.4 > openvpn.patch
The above command will operate recursively and find the differences, and place those differences in the patch file.

patch -p[num] < patchfile
patch [options] originalfile patchfile
Use the patch command as shown below to apply the hello.patch to the original hello.c source code.

$ patch < hello.patch
patching file hello.c

The following patch commands can be used to apply the patch to source tree.

patch -p3 < /root/openvpn.patch
patching file openvpn-2.3.2/aclocal.m4
patching file openvpn-2.3.2/build/Makefile.in
patching file openvpn-2.3.2/build/msvc/Makefile.in
…

note that we are executing the command from /usr/src/. The patch file contains all the filenames in absolute path format( from root ). So when we execute from /usr/src, without the “-p” option, it will not work properly.

-p3 tells the patch command to skip 3 leading slashes from the filenames present in the patch file. In our case, the filename in patch file is “/usr/src/openvpn-2.3.2/aclocal.m4″, since you have given “-p3″, 3 leading slashes, i.e. until /usr/src/ is ignored.

Redirects

Appends standard output to a file
2>redirects error to a file
2>> appends standard error to existing file
&>redirects both standout and std error to a file; if specified
< stdin
<> the specified file is used for both stdin and stdout

PROCESSES

KILL

kill -kill process or kill -term process or kill %2 ( were %2 is job id#)
Pgrep -u chuks -l ( list all chuks processes)
Pkill kill the main process to kill child process**
Ps axo ( specify what to be seen from man e.g pid,comm,nice,time ) pid

NICE
Generally from -20 ( most favorable) to 20( least favorable) the lesser the nice value the more priority the cpu gives a process and vice versa
To start Nice -n 0 httpd
To change a process then use
Renice -n 10 $ ( pgrep httpd) this will change all current running httpd process to 10
Then check with ps axo pind,comm,nice | grep httpd

pidoff will give you the process id of such

**Calculating Processor load**


Per CPU load average calculation formula: load average / # of cpu e.g

Per CPU load average calculation 1 Minute load average: 1.04 / 2 = 52%

https://scoutapm.com/blog/understanding-load-averages

A single-core CPU is like a single lane of traffic. Imagine you are a bridge operator … sometimes your bridge is so busy there are cars lined up to cross. You want to let folks know how traffic is moving on your bridge. A decent metric would be how many cars are waiting at a particular time. If no cars are waiting, incoming drivers know they can drive across right away. If cars are backed up, drivers know they’re in for delays.
So, Bridge Operator, what numbering system are you going to use? How about:
• 0.00 means there’s no traffic on the bridge at all. In fact, between 0.00 and 1.00 means there’s no backup, and an arriving car will just go right on.
• 1.00 means the bridge is exactly at capacity. All is still good, but if traffic gets a little heavier, things are going to slow down.
• over 1.00 means there’s backup. How much? Well, 2.00 means that there are two lanes worth of cars total — one lane’s worth on the bridge, and one lane’s worth waiting. 3.00 means there are three lane’s worth total — one lane’s worth on the bridge, and two lanes’ worth waiting. Etc.

This is basically what CPU load is. “Cars” are processes using a slice of CPU time (“crossing the bridge”) or queued up to use the CPU. Unix refers to this as the run-queue length: the sum of the number of processes that are currently running plus the number that are waiting (queued) to run.
Like the bridge operator, you’d like your cars/processes to never be waiting. So, your CPU load should ideally stay below 1.00. Also like the bridge operator, you are still ok if you get some temporary spikes above 1.00 … but when you’re consistently above 1.00, you need to worry.
So you’re saying the ideal load is 1.00?
Well, not exactly. The problem with a load of 1.00 is that you have no headroom. In practice, many sysadmins will draw a line at 0.70:
• The “Need to Look into it” Rule of Thumb: 0.70 If your load average is staying above > 0.70, it’s time to investigate before things get worse.
• The “Fix this now” Rule of Thumb: 1.00. If your load average stays above 1.00, find the problem and fix it now. Otherwise, you’re going to get woken up in the middle of the night, and it’s not going to be fun.
• The “Arrgh, it’s 3AM WTH?” Rule of Thumb: 5.0. If your load average is above 5.00, you could be in serious trouble, your box is either hanging or slowing way down, and this will (inexplicably) happen in the worst possible time like in the middle of the night or when you’re presenting at a conference. Don’t let it get there.
What about Multi-processors? My load says 3.00, but things are running fine!
Got a quad-processor system? It’s still healthy with a load of 3.00.
On multi-processor system, the load is relative to the number of processor cores available. The “100% utilization” mark is 1.00 on a single-core system, 2.00, on a dual-core, 4.00 on a quad-core, etc.
If we go back to the bridge analogy, the “1.00” really means “one lane’s worth of traffic”. On a one-lane bridge, that means it’s filled up. On a two-late bridge, a load of 1.00 means its at 50% capacity — only one lane is full, so there’s another whole lane that can be filled.
Same with CPUs: a load of 1.00 is 100% CPU utilization on single-core box. On a dual-core box, a load of 2.00 is 100% CPU utilization.
Multicore vs. multiprocessor
While we’re on the topic, let’s talk about multicore vs. multiprocessor. For performance purposes, is a machine with a single dual-core processor basically equivalent to a machine with two processors with one core each? Yes. Roughly. There are lots of subtleties here concerning amount of cache, frequency of process hand-offs between processors, etc. Despite those finer points, for the purposes of sizing up the CPU load value, the total number of cores is what matters, regardless of how many physical processors those cores are spread across.
Which leads us to a two new Rules of Thumb:
• The “number of cores = max load” Rule of Thumb: on a multicore system, your load should not exceed the number of cores available.
• The “cores is cores” Rule of Thumb: How the cores are spread out over CPUs doesn’t matter. Two quad-cores == four dual-cores == eight single-cores. It’s all eight cores for these purposes.
Bringing It Home
Let’s take a look at the load averages output from uptime:

```shell
~ $ uptime
23:05 up 14 days, 6:08, 7 users, load averages: 0.65 0.42 0.36
```

This is on a dual-core CPU, so we’ve got lots of headroom. I won’t even think about it until load gets and stays above 1.7 or so.
Now, what about those three numbers? 0.65 is the average over the last minute, 0.42 is the average over the last five minutes, and 0.36 is the average over the last 15 minutes. Which brings us to the question:
Which average should I be observing? One, five, or 15 minute?
For the numbers we’ve talked about (1.00 = fix it now, etc), you should be looking at the five or 15-minute averages. Frankly, if your box spikes above 1.0 on the one-minute average, you’re still fine. It’s when the 15-minute average goes north of 1.0 and stays there that you need to snap to. (obviously, as we’ve learned, adjust these numbers to the number of processor cores your system has).
So # of cores is important to interpreting load averages … how do I know how many cores my system has?
cat /proc/cpuinfo to get info on each processor in your system. Note: not available on OSX, Google for alternatives. To get just a count, run it through grep and word count: `grep ‘model name’ /proc/cpuinfo | wc -l`

cut options = -d , -c ( character) or -f or b(byte almost same as character)
cut
-d specifies which delimiter to use e.g uname -ar | cut -d”:” -f1,2 ( this means use “:’ as delimiter and first field and second field
or cut -d”,” -f 3- test.cv ( this will filter in the file fields separated by “,” from d 3rd field to the end or u can don cut -d”,”-f -3 test.cv
-s will suppress lines that don’t have the delimiter option and not display it
using the option** —output-delimiter=$ test.cv ( u can change the output limiter to come with $ instead of the what is specified e.g
```shell
[root@Centos7baba data]# cat sample
fname,lname,age,salary hello
nancy,davolio,33,$30000 jaahaha
erin,borakova,28,$25250 asdfasdf
tony,raphael,35,$28700 asdfasdfdsf


[root@Centos7baba data]# cut -d”,” -f 1-3 —output-delimiter=”%” sample
fname%lname%age
nancy%davolio%33
erin%borakova%28
tony%raphael%35
[root@Centos7baba data]#
```
—*complement will do the opposite of what the output string is e.g:
```shell
[root@Centos7baba data]# echo 1234567890 | cut -c 1-5
12345
[root@Centos7baba data]# echo 1234567890 | cut -c 1-5 —complement
67890
```
**sort** - used to sort lists..
use -u or pipe with uniq to get unique instances and remove dups..e.g:
```shell
[root@Centos7baba data]# cat output1
123456
123456
abcdef
[root@Centos7baba data]# cat output1 | uniq
123456
abcdef
```

removing the extra line “123456” or
```
root@Centos7baba data]# sort -u output1
123456
abcdef
[root@Centos7baba data]#
```

REDIRECTION

/dev/null 2>&1 note that

1= standard output
2= error, so
/dev/null 2>&1 means dump standard error and output to the same file “/dev/null” which in this case is nothing so output is surpressed.

Usuage when redirecting output and error to a file u must use format like here:

ping -c50000 google.com > /dev/null 2>&1

APACHE

apachetl -configtest
htpasswd /usr/uj/jurbanek/.htpasswd dave

Apache virtual Host configs:

DocumentRoot “/var/www/html/“

#DirectoryIndex index.html
AllowOverride None
Options Indexes FollowSymLinks


**SED**

Sed is commonly used for command substitution >>
options: i = makes change permanent in file not just stdout
s= substitutes a phrase or smth for another
g = changes every occurrence of a phrase

example >>>>>
```shell
sed -i ‘s/BOOTPROTO=”dhcp”/BOOTPROTO=”STATIC”/g’ /etc/sysconfig/network-scripts/ifcfg-enp0s3

[root@Alpha ~]# cat /etc/sysconfig/network-scripts/ifcfg-enp0s3
TYPE=”Ethernet”
BOOTPROTO=”STATIC”
DEFROUTE=”yes”
```
```
cat < /etc/salt.conf

EOF
```
this opens up takes input and overwrites the existing file ..make sure to close by adding at the end to tell Cat to stop

yum history —lists recent yum events by id and users e.g

root@webapache1 /wwwroot/htdocs/admin.src.bah.com $ yum history
Loaded plugins: product-id, rhnplugin, search-disabled-repos
This system is receiving updates from RHN Classic or Red Hat Satellite.

ID | Login user | Date and time | Action(s) | Altered
45 | Jason ... <jcalafiore>   | 2016-06-06 11:47 | Install        |    1
44 | System <unset>           | 2016-06-04 08:22 | E, I, U        |   58
43 | System <unset>           | 2016-04-23 08:25 | E, I, U        |   48
yum history info 45 —-gives info on the id number “45”

ssh copyid you
to use this both public and priv keys must be in the same .ssh / then you can use it
even if you have only the publick key you can create a blank priv key
and name must be id_rsa
id_rsa.pub

e.g cokonkwo@DBT01:~/.ssh> ll
total 16
-rw———- 1 cokonkwo domain users 398 May 24 10:22 authorized_keys
-rw-r—r— 1 cokonkwo domain users 398 May 27 15:15 chukspubkey.pub.bak
-rw-r—r— 1 cokonkwo domain users 0 May 27 15:55 id_rsa
-rw———- 1 cokonkwo domain users 398 May 24 10:42 id_rsa.pub
-rw-r—r— 1 cokonkwo domain users 444 May 24 11:10 known_hosts

cokonkwo@CIRTLDBT01:~/.ssh> ssh-copy-id cokonkwo@CIRTLDBT02.bah-cirt.ds.bah.com
The authenticity of host ‘cirtldbt02.bah-cirt.ds.bah.com (10.13.246.39)’ can’t be established.
ECDSA key fingerprint is b9:64:44:af:4c:95:d1:b7:30:ea:fc:d8:2b:6a:25:3c [MD5].
Are you sure you want to continue connecting (yes/no)? yes
/usr/bin/ssh-copy-id: INFO: attempting to log in with the new key(s), to filter out any that are already ins
/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed — if you are prompted now it is to install the
cokonkwo@cirtldbt02.bah-cirt.ds.bah.com’s password:
Number of key(s) added: 1
Now try logging into the machine, with: “ssh ‘cokonkwo@DBT02.chukky.ds.tech.com’”
and check to make sure that only the key(s) you wanted were added.

————SELINUX————

targeted mode by default ==for managing process and folders not users..
ls -Za to show contexts
Changing context type in selinux
chcon -tR type file/folder were R is recursive
or restorecon -vR /var/ww/ were V is verbose * This is a cheat method here and it will restore all files or folder to their default contexts if u don’t want to type or know what the context is. Nome contexts are inherited like permissions and ACLS so if u mv a file from one location to another it will maintain its permission and selinux context and not inherit the new locations. So always use cp when moving a file so that it will adopt the new permissions.

so fixing we can do it this way chcon -t httpd_sys_content_t index.html or
restorecon -vR .were v again is verbose.

Note chcon changes wont survive system reboot as the file system relabels itself to what is saved in the selinux entry in /etc/selinux/targeted/contexts/files/file.contexts

root@examprep2 ~]# ls -lZ
-rw———-. root root system_u:object_r:admin_home_t:s0 anaconda-ks.cfg
-rw-r—r—. root root system_u:object_r:admin_home_t:s0 file1
-rw-r—r—. root root unconfined_u:object_r:boot_t:s0 hello
-rw———-. root root system_u:object_r:admin_home_t:s0 initial-setup-ks.cfg

Change temporarily filecontext to admin_home and selinux user to system_u for file hello as shown below:

[root@examprep2 ~]# chcon -t admin_home_t -u system_u hello
[root@examprep2 ~]# ls -lZ
-rw———-. root root system_u:object_r:admin_home_t:s0 anaconda-ks.cfg
-rw-r—r—. root root system_u:object_r:admin_home_t:s0 file1
-rw-r—r—. root root system_u:object_r:admin_home_t:s0 hello
-rw———-. root root system_u:object_r:admin_home_t:s0 initial-setup-ks.cfg

Then reverting all the content of /root/ back to default prior to the chcon above

[root@examprep2 ~]# restorecon -v ~/*
restorecon reset /root/hello context system_u:object_r:admin_home_t:s0->system_u:object_r:boot_t:s0

[root@examprep2 ~]# ls -lZ
-rw———-. root root system_u:object_r:admin_home_t:s0 anaconda-ks.cfg
-rw-r—r—. root root system_u:object_r:admin_home_t:s0 file1
-rw-r—r—. root root system_u:object_r:boot_t:s0 hello
-rw———-. root root system_u:object_r:admin_home_t:s0 initial-setup-ks.cfg

qç
hello file is now back to boot_t file context type

To make permanent file context changes make use semanage fcontext -a to add the selinux policy and restorecon to apply it.
semanage fcontext policy options are

a = add
t= file context for file context
-s for selinux user context

e.g.

semanage fcontext -a -t admin_home_t -s user_u /root/hello

[root@examprep2 ~]# ls -lZ

-rw———-. root root system_u:object_r:admin_home_t:s0 anaconda-ks.cfg
-rw-r—r—. root root system_u:object_r:admin_home_t:s0 file1
-rw-r—r—. root root system_u:object_r:boot_t:s0 hello
-rw———-. root root system_u:object_r:admin_home_t:s0 initial-setup-ks.cfg

Until Restorecon is done still the same as above

[root@examprep2 ~]# restorecon -vF /root/hello
restorecon reset /root/hello context system_u:object_r:boot_t:s0->user_u:object_r:admin_home_t:s0

Now look

[root@examprep2 ~]# ls -lZ
-rw———-. root root system_u:object_r:admin_home_t:s0 anaconda-ks.cfg
-rw-r—r—. root root system_u:object_r:admin_home_t:s0 file1
-rw-r—r—. root root user_u:object_r:admin_home_t:s0 hello
-rw———-. root root system_u:object_r:admin_home_t:s0 initial-setup-ks.cfg

Now rebooting will keep the file permissions the same :

[root@examprep2 ~]# uptime
15:07:37 up 1 min, 1 user, load average: 0.87, 0.60, 0.24
[root@examprep2 ~]# ls -Z
-rw———-. root root system_u:object_r:admin_home_t:s0 anaconda-ks.cfg
-rw-r—r—. root root system_u:object_r:admin_home_t:s0 file1
-rw-r—r—. root root user_u:object_r:admin_home_t:s0 hello
-rw———-. root root system_u:object_r:admin_home_t:s0 initial-setup-ks.cfg
[root@examprep2 ~]#

doing restorecon -v /root will change hello file to defaut in /root aka ~

Troubleshooting Selinux

logs in /var/log/audit/audit.log but install setroubleshoot-server
now you can view alerts better in /var/log/messages by doing sealert -a /var/log/audit/audit.log to view
Enhanced seleniux errors and solutions!!

SELinux is preventing /usr/sbin/httpd from getattr access on the file /content/index.html.

* Plugin restorecon (94.8 confidence) suggests **

If you want to fix the label.
/content/index.html default label should be httpd_sys_content_t.
Then you can run restorecon.
Do

/sbin/restorecon -v /content/index.html
* Plugin catchall_labels (5.21 confidence) suggests *

If you want to allow httpd to have getattr access on the index.html file
Then you need to change the label on /content/index.html
Do

semanage fcontext -a -t FILE_TYPE ‘/content/index.html’
Do s

sealert -l gui for troubleshooting
Setsebool is used for setting boolean rules
boolean flags are simply yes or no i.e 1 for yes or 0 for no.
you can use boolean flags for troubleshooting instead of changing contexts of files
to see boolean options that can be set do —getsebool -a then grep result of it since many options
setssebool -P ( P makes changes permanent when rebooted) booloption 1/0 i.e on /off
view changes in /etc/selinux/targeted/modules/active/booleans.local

MYSQL
show slave status \G ;; shows slave status of a DB if there is replication
SHOW PROCESSLIST \G; ;; shows process list of slaves when run on the master db
mysql> SHOW SLAVE HOSTS;; shows basic information about slaves.

update mysql user hostip
UPDATE mysql.user SET host = {newhost} WHERE user = {youruser}

show grants for’replicate’@’10.10.228.%’;
changing replciation ip info ….

show master status
stop slave
CHANGE MASTER TO MASTER_HOST=’10.10.228.132’; ( ip of db1, while on dbt2 )
START SLAVE;
pager less
show slave status \G; *NOTE “\G” helps display your table in row form instead of column form
or use pager less then command press “q” to escape from pager

SCRIPTING TIDBITS
echo -e “ I am blessed\n” = e enables interpretation of backlashes e.g “\n” in this case new line

echo -n = don’t put new line:x

Terminal prompt
PS1=”[\033[01;31m]\u[\033[00m][\033[31m]@[\033[01;31m]\h \$(pwd)[\033[00m] $ “ ( put this in .bashrc file to make username @hostname and pwd all red

infocmp shows d number of colors put works with

Create a keyfile from urandom >>> can be used for password
dd if=/dev/urandom of=/root/keydocs bs=1024 count=4

!/bin/sh
Script to start Resilient CAF services
PIDFILE=/opt/resilientCAF/log/run.pid

if [ -f $PIDFILE ];
then
PID=cat log/run.pid
echo “ERROR: ResilientCAF already running under PID: $PID”
echo
else
nohup python run.py > /dev/null 2>&1 &
echo $! > log/run.pid
PID=cat log/run.pid
echo “ResilientCAF started under PID: $PID”
echo
Fi

http://www.cyberciti.biz/hardware/howto-linux-hard-disk-encryption-with-luks-cryptsetup-command/ cryptsetup..

Fping useful tool designed better for scripting.
Quickly generate a largefile with random generate numbers

dd if=/dev/urandom of=/baba bs=1024 count=1048576
were count is file size ( approx 1.1GB) bs buffer size how much per second in transfer 1 kilobyte >>>>results below:

1048576+0 records in
1048576+0 records out
1073741824 bytes (1.1 GB) copied, 53.5423 s, 20.1 MB/s

Last command >> searches back through the file /var/log/wtmp (or the file designated by the -f flag) and displays a list of all users logged in (and out) since that file was created.
last or last reboot show users or last reboot times respectively.

MAIL —SMTP

Very good explanations here : https://technet.microsoft.com/en-us/magazine/cc160769.aspx
issue commands:

$ telnet localhost 25
EHLO mail.chukky.tech.com EHLO (or HELO) identifies the server initiating the connection. It also tells the receiving server to clear its slate.
MAIL FROM:okonkwo_chuks@chukkytech.com
RCPT TO:okonkwo_chuks@chukkytech.com
DATA DATA
There are no parameters for this command. Barring error, the server will reply:
354 Enter mail, end with “.” on a line by itself
SUBJECT: Test from CARTLMAILP1
This is a test message
.

Generating Secure passwd in RHEL
https://www.openssl.org/docs/manmaster/apps/passwd.html note option 1 to creat md5crypt

Runlevels
systemctl list-units -t target : this will show you the loaded targets ( or runlevels)

[root@rhel7 ~]# systemctl list-units -t target
UNIT LOAD ACTIVE SUB DESCRIPTION
basic.target loaded active active Basic System
cryptsetup.target loaded active active Encrypted Volumes
getty.target loaded active active Login Prompts
local-fs-pre.target loaded active active Local File Systems (Pre)
local-fs.target loaded active active Local File Systems
multi-user.target loaded active active Multi-User System
graphical.target loaded inactive dead Graphical Interface —> this is graphical or user runlevel
To switch from GUI to CLI: systemctl isolate multi-user.target
To switch from CLI to GUI: systemctl isolate graphical.target
To set the CLI as a default runlevel (target in systemd terminology): systemctl set-default multi-user.target. Analogously for GUI: systemctl set-default graphical.target
*CLI = Command Line Interface = command-line mode

systemctl get-default ( to get current runlevel)
systemctl set-default multi-user.target
** there are 4 major target modes:
Multi-user.target , for allowing multiple users to login usually text based interface cmdline with networking
Graphical.target , this is known as gui or desktop version
emergency.target, this will put you in root with ro file system for
Resuce target— puts u in single user target and puts minimal resources needed for troubleshooting the system
u can get dependencies of a target:
systemctl list-dependencies graphical.target | grep multi-user target

At for scheduling jobs
http://tecadmin.net/one-time-task-scheduling-using-at-commad-in-linux/

Reposync
The Reposync command can be used to mirro a repo to local repo
reposync -r base -p /repo/centos/7/os/x86_64/ were r is the repoid gotten from etc/yum.reposd/centosbase.repo or wahterve
-p is the path were packages will be downloaded to
—norepopath : will not include name of repo as path of downloaded packages ( by default without this name of repo
Is added as a path
-n : gets newest

Background ,foreground and nohup

When a process is running ctl-z will stop and not KILL the process , use jobs or jobs -l to list its id and process number
,While ctrl-c will kill and terminate process
Put in background with ping -c50000 google.com > /dev/null 2>&1 &
root@openldapclient ~]# jobs -l
[1]+ 15084 Stopped ping -c100 google.com >> error.txt
Put it in the background by typing bg (job id)
[root@openldapclient ~]# fg
ping -c100 google.com >> error.txt

Bring a background job up front by typing fg job id if any if not it will take the only job in background
root@openldapclient ~]# jobs -l
[1]+ 15084 Stopped ping -c100 google.com >> error.txt
[root@openldapclient ~]# fg
ping -c100 google.com >> error.txt

Nohup will makesure job running does not disconnect when a session is turned off or receive a sighup command. Put it in the background
And it will run in the background
Any errors or background output message are kept in nohup,out,
( if no errors there will be nothing there) file or you can specify were logs will be kept. E.g
◊ Nohup sleep -25 & puts the action in background will output tp default file created usually nohup.out
◊ Nohup sleep -25 > output.txt & this will run in the background too but puts all output and error files to output.txt

Pushd, popd and dirs
http://notes.jerzygangi.com/moving-around-in-linux-with-pushd-popd-and-dirs/

Bash_profile = in root contain what loads when you enter a login shell ..
Bash_rc = will load when you enter an interactive shell
Note when you loing into a server for first time you are inside a login shell but when you su a user you re nolonger in a login shell but an inteeractive one
But when you do su - user u enter a login shell. Or su -l user
http://www.joshstaiger.org/archives/2005/07/bash_profile_vs.html

Stuff you putt in bash_profile when only show up when you log in there so u can put some stats in it for a system when u login there u will see it.

SAMBA
Pdbedit ( many options)
Pdbedit -L shows users
Smbstatus - to see connections status
Smbpasswd -a ( users) add a user to samber and prompts for password