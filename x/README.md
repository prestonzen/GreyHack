Commands
x a [ip_address] -- get info about IP, basically nmap but better
x b [ip_address] [port] -- mem scanner
x c [ip_address] [port] [memory_address] [vulnerability] -- exploit
x rl [ip_address] [port] [user] [password] -- corrupt Logs or remove logs = rl
x rlssh [ip_address] [port] [user] [password] -- connect & corrupt Logs
x installSSH
x z [username] -- user switcher
x me -- local router & pc + public router & pc ips
x upd -- update
x c ip router -- you should use it if there's no open ports or if there's no vulns.

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