#Commands

##Authentication
x auth [passwd] -- get access to x

##Connections
x aserver -- safe connect to aserver
x installSSH

##Hacking
x ipscan [ip_address] -- get info about IP, basically nmap but better
x vulnscan [ip_address] [port] -- Library vulnerability scanner
x exploit [ip_address] [port] [memory_address] [vulnerability] -- exploit
x exploit [ip_address] [router] -- you should use it if there's no open ports or if there's no vulns.

##System
x me -- local router & pc + public router & pc ip info
x upd -- update
x z [username] -- user switcher

##Anti-Forensics
x rlhost --removes logs on the local host
x rlaserver -- corrupt aserver's system.log
x rl [ip_address] [port] [user] [password] -- corrupt Logs/remove logs = rl
x rlssh [ip_address] [port] [user] [password] -- connect & corrupt Logs

---
#Attack Flow
x a to get info about target
x b to scan target's libraries
x c to exploit on those libraries
x rlssh + x rl are made for 22 port ONLY
so, at first you'd like to do x installSSH on the remote machine
x z just switches users
x me - well, you can see this in the description
x upd is basically
apt-get update ; apt-get upgrade

--- Examples ---
#Corrupting target log files of the attacked server
x rl aserver 
