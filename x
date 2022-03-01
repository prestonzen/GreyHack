///x b [ip_address] [port] -- mem scanner
///x c [ip_address] [port] [memory_address] [vulnerability] -- exploit
///x rl [ip_address] [port] [user] [password] -- corrupt Logs
///x rlssh [ip_address] [port] [user] [password] -- connect & corrupt Logs
///x installSSH
///x z [username] -- user switcher
///x me -- local router & pc + public router & pc ips
///x upd -- update

pendingUpdating = function(folderPath)
	pendingUpdate = []
	targetFolder = get_shell.host_computer.File(folderPath)
	if targetFolder != null then
		files = targetFolder.get_files
		for itemFile in files
			output = aptclient.check_upgrade(itemFile.path)
			if output == true then
				pendingUpdate.push(itemFile.name)
			end if
		end for
	end if
	return pendingUpdate
end function
getPassword = function(userPass)
    if userPass.len != 2 then exit("decipher: " + file.path + " wrong syntax")
    password = cryptools.decipher(userPass[1])
    return password
end function
///
a = function(argumentA)
    print("<b><color=#ffac00>WHOIS: </b></color>\n" + whois(argumentA))
    print("<b><color=#ffac00>PORTS: </b></color>")
    ip = argumentA
    isLan = is_lan_ip(ip)
    if isLan then
        router = get_router
    else
        router = get_router(ip)
    end if
    if not isLan then
        ports = router.used_ports
    else
        ports = router.device_ports(ip)
    end if
    info = "<b>PORT STATE SERVICE VERSION LAN</b>"
    if ports.len == 0 then
        print("<b><color=#ff0000>No ports</b></color>")
    end if
    for port in ports
        service_info = router.port_info(port)
        lan_ips = port.get_lan_ip()
        port_status = "open"
        if port.is_closed and not isLan then
            port_status = "closed"
        end if
        info = info + "\n" + port.port_number + " " + port_status + " " + service_info + " " + lan_ips
    end for
    print(format_columns(info))
    print("<b><color=#ffac00>KERNEL: </b></color>\n" + router.kernel_version)
    exit("<b><color=#ffac00>FIREWALL RULES: </b></color>\n" + router.firewall_rules)
end function
b = function(argumentA, argumentB)
    metaxploit = include_lib("/lib/metaxploit.so")
    if not metaxploit then exit("<b><color=#ff0000>Couldn't find Metaxploit.so</b></color>")
	net_session = metaxploit.net_use(argumentA, argumentB.to_int)
    if not net_session then exit("<b><color=#ff0000>Can't connect to net session!</b></color>")
    metaLib = net_session.dump_lib
    print("<b><color=#ffac00>Scanning </b></color>" + metaLib.lib_name + "<b><color=#ffac00> v.</b></color>" + metaLib.version)
    listMem = metaxploit.scan(metaLib)
    if listMem.len == 0 then exit("<b><color=#ffac00>No result</b></color>")
    print("<b><color=#ffac00>Issues in: </b></color>" + listMem.len + " <b><color=#ffac00>memory zones</b></color>")
    index = 1
    for itemMem in listMem
	    print(index +": <b>[</b>" + itemMem + "<b>]</b>")
	    index = index + 1
    end for
    for mem in listMem
        print("<b><color=#ffac00>Target: </color>" + mem + "</b>")
        requirements_vulns = metaxploit.scan_address(metaLib, mem)
        a = requirements_vulns.split("Unsafe check: ")
        if a.len > 1 and a.len < 3 then
        b = a[1].split(". Buffer overflow.")
        r = b[0].split(" ")
        print("<b><color=#ff0000>Vulnerability: </color>" + r[3])
        else if a.len > 2 and a.len < 4 then
        b = a[1].split(". Buffer overflow.")
        c = a[2].split(". Buffer overflow.")
        r = b[0].split(" ")
        t = c[0].split(" ")
        print("<b><color=#ff0000>Vulnerability: </color>" + r[3] + "\n<b><color=#ff0000>Vulnerability: </color>" + t[3])
        else if a.len > 3 and a.len < 5 then
        b = a[1].split(". Buffer overflow.")
        c = a[2].split(". Buffer overflow.")
        d = a[3].split(". Buffer overflow.")
        r = b[0].split(" ")
        t = c[0].split(" ")
        y = c[0].split(" ")
        print("<b><color=#ff0000>Vulnerability: </color>" + r[3] + "\n<b><color=#ff0000>" + "Vulnerability: </color>" + t[3] + "\n<b><color=#ff0000>" + "Vulnerability: </color>" + y[3])
        else if a.len > 4 and a.len < 6 then
... (194 lines left)
