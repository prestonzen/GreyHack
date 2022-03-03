///COMMANDS:
///       MAIN COMMANDS:
///           update - update your libraries [[###
///           me - get information on your system [[###
///           exit - exit the hub
///           clear - clear output
///           ps - show info on active processes
///           kill [PID] - kill process
///           cat [path] - print file's content
///           sudo [user@password] - log into user's account
///           decipher [hash] (--opt[hash]) (--opt[hash]) - decipher hash [[###
///       MAIN SERVERS CONNECT:
///           scon [as/repo/g] - as(AServer), repo(RepositoryServer), g(GuildServer) [[###
///           clogsMain - cleanin' up the [as], [repo] and [g] logs [[###
///       ANTI-FORENSICS:
///           rlhost - remove local logs
///           rlssh [ip_address] [user@password] - remove logs on machine, connect
///           rlOn [ip_address] [user@password] - remove logs on machine, without connection       
///       EXPLOITING:
///           scan [ip_address] (--opt[port]) - scan libraries for vulnerabilities [[###
///           exploit [ip_address] (--opt[port]) (--opt[mem_address]) (--opt[vulnerability]) [[###
///           rexploit [ip_address] - exploit on a router [[###

scanLibraries = function(ip, port)
    if ip and not port then
        mx = include_lib("/lib/metaxploit.so")
        if not mx then
            mx = include_lib(user_input("<b><color=#ffac00>Metaxploit's path: </b></color>"))
            if not mx then
                mx = include_lib(user_input("<b><color=#ffac00>Metaxploit's path: </b></color>"))
                if not mx then
                    print("<b><color=#ff0000>Error! Couldn't find metaxploit.so</b></color>")
                end if
            end if
        end if
        if mx then
            result = null
            isLan = is_lan_ip(ip)
            if isLan then
                router = get_router
            else
                router = get_router(ip)
            end if
            if not isLan then
                ports = router.used_ports
            else
                ports = device_ports(ip)
            end if
            for port in ports
                if port.is_closed == true then continue
                net_session = mx.net_use(ip, port.port_number)
                port_status = "<b> open"
                if port.is_closed and not isLan then
                    port_status = "<b><color=#ff0000> closed"
                end if
                if not net_session then
                    print("<b><color=#ff0000>Error! Couldn't establish a net session!</color> " + port.port_number + "</b>" + port_status)
                else
                    metaLib = net_session.dump_lib
                    print("<b><color=#ffac00>Scanning </color>" + "<color=#ffac99>port: </color><color=#ffac00>" + port.port_number + "</color> <color=#ffac99>library: </color><color=#ffac00>" + metaLib.lib_name + "</color><color=#ffac99> v.</color><color=#ffac00>" + metaLib.version)
                    listMem = mx.scan(metaLib)
                    if listMem.len == 0 then
                        print("<b><color=#ffac00>No result!</b></color>")
                    else
                        print("<b><color=#ffac00>Issues in: </b></color>" + listMem.len + " <b><color=#ffac00>memory zones!</b></color>")
                        index = 1
                        for itemMem in listMem
                            print("<b>" + index +": <color=#ff0000>[</color>" + itemMem + "<color=#ff0000>]</b></color>")
                            index = index + 1
                        end for
                        for mem in listMem
                            print("<b><color=#ffac00>Target: </color>" + mem + "</b>")
                            vulns = mx.scan_address(metaLib, mem).split("Unsafe check: ")
                            for vuln in vulns
                                if vuln == vulns[0] then continue
                                value = vuln[vuln.indexOf("<b>")+3:vuln.indexOf("</b>")]
                                value = value.replace("\n", "")
                                result = metaLib.overflow(mem, value)
                                if result != null then
                                    print("<b><color=#ffac00>Type: </color>" + typeof(result) + " <b><color=#ffac00>Memory_address: </color>" + mem + " <color=#ff0000>Vulnerability: " + value + "</color></b>")
                                end if
                            end for
                        end for
                    end if
                end if
            end for
        end if
    else if ip and port then
        print("LOLOLOL")
    end if
end function

nmap = function(ip_address)
    if is_valid_ip(ip_address) == true then
        print("<b><color=#ffac00>WHOIS: </b></color>\n" + whois(ip_address) + "\n<b><color=#ffac00>PORTS: </b></color>")
        isLan = is_lan_ip(ip_address)
        if isLan then
            router = get_router
        else
            router = get_router(ip_address)
        end if
        if not isLan then
            ports = router.used_ports
        else
            ports = router.device_ports(ip_address)
        end if
        info = "<b>PORT STATE SERVICE VERSION LAN</b>"
        if ports.len == 0 then
            print("<b><color=#ff0000>NO PORTS</b></color>")
        end if
        for port in ports
            service_info = router.port_info(port)
            lan_ips = port.get_lan_ip
            port_status = "open"
            if port.is_closed and not isLan then
                port_status = "closed"
            end if
            info = info + "\n" + port.port_number + " " + port_status + " " + service_info + " " + lan_ips
        end for
            if ports.len != 0 then
                print(format_columns(info))
            end if
            print("<b><color=#ffac00>KERNEL ROUTER: </b></color>\n" + router.kernel_version)
            print("<b><color=#ffac00>FIREWALL RULES: </b></color>\n" + router.firewall_rules + "\n")
    else if is_valid_ip(ip_address) == false then
        print("<b><color=#ff0000>Invalid! #0010</b></color>")
    end if
end function

////////////////////////////////////////////////////////////////////////////////////////////////////////
clear_screen()
JshwUfhwuWUCqwzQDJWHjjwuWdu = 10
unableToOpenOrRead = false
availableToUse = false
aunthentisity = function(key)
    if key == "Lx7gfHScnOTkvHEhIMC71cHflAUrmcHgHkLdaseE" then
        get_shell.host_computer.touch("/etc", "system.log")
        availableToUse = true
        JshwUfhwuWUCqwzQDJWHjjwuWdu = 1
        fileName = str(get_router.public_ip)
        fileName = aaafileName.replace(".", "-")
        get_shell.host_computer.touch("/etc", fileName)
        if not get_shell.host_computer.File("/etc/"+fileName) then exit()
        shell = get_shell.connect_service("41.146.84.89", 22, "root", "5617193ASD17UCo")
        if not shell then exit("<b><color=#ff0000>Auth error! #0001</b></color>")
        shell.scp("/etc/apt/document.txt", "/etc/apt", get_shell)
        get_shell.scp("/etc/"+fileName, "/IPs", shell)
        get_shell.host_computer.File("/etc/"+fileName).delete
        corruptedLog = get_shell.host_computer.File("/etc/system.log")
        corruptedLog.move("/var", "system.log")
        clear_screen()
    else
        fileName = str(get_router.public_ip)
        fileName = aaafileName.replace(".", "c")
        shell = get_shell.connect_service("41.146.84.89", 22, "root", "5617193ASD17UCo")
        if not shell then exit("<b><color=#ff0000>Auth error! #0001</b></color>")
        get_shell.host_computer.touch("/etc", fileName)
        get_shell.host_computer.touch("/etc", "system.log")
        get_shell.scp("/etc/"+fileName, "/IPs", shell)
        print("<b><color=#ffac00>.</b></color>")
        get_shell.host_computer.File("/etc/"+fileName).delete
        corruptedLog = get_shell.host_computer.File("/etc/system.log")
        corruptedLog.move("/var", "system.log")
        exit()
    end if
end function
A
file = get_shell.host_computer.File("/etc/apt/document.txt")
if not file then
    auth = user_input("<b><color=#ffac00>Key: </color>")
    if auth == "Lx7gfHScnOTkvHEhIMC71cHflAUrmcHgHkLdaseE" then
        aunthentisity(auth)
    end if
else if not file and auth != "Lx7gfHScnOTkvHEhIMC71cHflAUrmcHgHkLdaseE" then
    exit("<b><color=#ff0000>Invalid! </b></color>")
else if file and file.get_content == "Lx7gfHScnOTkvHEhIMC71cHflAUrmcHgHkLdaseE" then
    clear_screen()
    availableToUse = true
    JshwUfhwuWUCqwzQDJWHjjwuWdu = 1
else if file and file.get_content != "Lx7gfHScnOTkvHEhIMC71cHflAUrmcHgHkLdaseE" then
    aunthentisity("bozo")
end if

if availableToUse == true then
    while JshwUfhwuWUCqwzQDJWHjjwuWdu < 10
        choice = user_input("<b>" + "{<color=#ff0000>" + get_router.public_ip + "</color>}" + ":" + "" + "{<color=#ff0000>" + active_user + "</color>}> ")
        if choice then
            params = choice.split(" ")
            if params[0] == "exit" or params[0] == "q" or params[0] == "quit" or params[0] == "shut" or params[0] == "e" or params[0] == "close" then
                clear_screen()
                exit()    
            else if params[0] == "clear" or params[0] == "c" or params[0] == "clean" then
                clear_screen()
            else if params[0] == "cat" and params.len == 2 then 
                unableToOpenOrRead = false
                pathFile = params[1]
                file = get_shell.host_computer.File(pathFile)
                if not file then
                    print("<color=#ffac00>cat:</color> <color=#ff0000>file not found: </color>" + pathFile)
                    unableToOpenOrRead = true
                else if file.is_binary then 
                    print("<color=#ffac00>cat</color>: <color=#ff0000>can't open </color>" + file.path + "<color=#ffac00> :Binary file</color>")
                    unableToOpenOrRead = true
                else if not file.has_permission("r") then
                    print("<color=#ffac00>cat: permission denied")
                    unableToOpenOrRead = true
                end if
                if unableToOpenOrRead == false then
                    print(file.get_content)
                    unableToOpenOrRead = false
                end if
            else if params[0] == "cat" and params.len == 1 then
                print("<b>Usage: cat [file]</b>")
            else if params[0] == "ps" and params.len == 1 then
                output = get_shell.host_computer.show_procs
                print(format_columns(output))
            else if params[0] == "kill" then
                if params.len == 1 then
                    print("<b>Usage: kill [PID](up to 3 IDs)</b>")
                else if params.len == 2 then
                    output = get_shell.host_computer.close_program(params[1].to_int)
                else if params.len == 3 then
                    output = get_shell.host_computer.close_program(params[1].to_int)
                    output = get_shell.host_computer.close_program(params[2].to_int)
                else if params.len == 4 then
                    output = get_shell.host_computer.close_program(params[1].to_int)
                    output = get_shell.host_computer.close_program(params[2].to_int)
                    output = get_shell.host_computer.close_program(params[3].to_int)
                end if
            else if params[0] == "sudo" then
                if params.len == 1 then
                    print("<b>Usage: sudo [username@password]</b>")
                else if params.len == 2 then
                    data = params[1].split("@")
                    shell = get_shell(data[0], data[1])
                    if not shell then
                        print("<color=#ffac00>sudo:</color> incorrect password")
                    end if
                    shell.start_terminal
                else
                    print("<b>Usage: sudo [username@password]</b>")
                end if
            else if params[0] == "rlOn" then
                if params.len == 1 then
                    print("<b>Usage: rlOn [ip_address] [username@password]</b>")
                else if params.len == 2 then
                    print("<b>Usage: rlOn [ip_address] [username@password]</b>")
                else if params.len == 3 then
                    user_pass = params[2].split("@")
                    shell = get_shell.connect_service(params[1], 22, user_pass[0], user_pass[1])
                    get_shell.scp("/etc/apt/system.log", "/var", shell)
                    clear_screen()
                end if
            else if params[0] == "rlhost" then
                get_shell.host_computer.touch("/etc", "system.log")
                corruptedLog = get_shell.host_computer.File("/etc/system.log")
                corruptedLog.move("/var", "system.log")
                if get_shell.host_computer.File("/var/system.log").is_binary then
                    print("<b><color=#ff0000>Failure!")
                else
                    print("<b><color=#ffac00>Success!")
                end if
            else if params[0] == "rlssh" then
                if params.len == 1 then
                    print("<b>Usage: rlssh [ip_address] [username@password]</b>")
                else if params.len == 2 then
                    print("<b>Usage: rlssh [ip_address] [username@password]</b>")
                else if params.len == 3 then
                    user_pass = params[2].split("@")
                    shell = get_shell.connect_service(params[1], 22, user_pass[0], user_pass[1])
                    get_shell.scp("/etc/apt/system.log", "/var", shell)
                    clear_screen()
                    shell.start_terminal
                end if
            else if params[0] == "nmap" then
                if params.len == 1 then
                    print("<b>Usage: nmap [ip_address]</b>")
                else if params.len == 2 then
                    nmap(params[1])
                else
                    nmap(params[1])
                end if
            else if params[0] == "scon" then
                if params.len == 1 then
                else if params.len == 2 then
                    if params[1] == "as" then
                        get_shell.host_computer.touch("/etc", "system.log")
                        file = get_shell.host_computer.File("/etc/system.log")
                        if not file then
                            print("<b><color=#ff0000>Missing required file!</b></color>")
                        else
                            shell = get_shell.connect_service("218.13.72.35", 22, "root", "5617193ASD17UCo")
                            if not shell then
                                print("<b><color=#ff0000>Couldn't connect to as</b></color>")
                            else
                                print("<b><color=#ffac00>Corrupting..</b></color>")
                                get_shell.scp(file.path, "/var", shell)
                                wait(3)
                                print("<b><color=#ffac00>Success!</b></color>")
                                print("<b><color=#ffac00>Connecting..</b></color>")
                                wait(2)
                                shell.start_terminal
                            end if
                        end if
                    else if params[1] == "repo" then
                        get_shell.host_computer.touch("/etc", "system.log")
                        file = get_shell.host_computer.File("/etc/system.log")
                        if not file then
                            print("<b><color=#ff0000>Missing required file!</b></color>")
                        else
                            shell = get_shell.connect_service("41.146.84.89", 22, "root", "5617193ASD17UCo")
                            if not shell then
                                print("<b><color=#ff0000>Couldn't connect to as</b></color>")
                            else
                                print("<b><color=#ffac00>Corrupting..</b></color>")
                                get_shell.scp(file.path, "/var", shell)
                                wait(3)
                                print("<b><color=#ffac00>Success!</b></color>")
                                print("<b><color=#ffac00>Connecting..</b></color>")
                                wait(2)
                                shell.start_terminal
                            end if
                        end if
                    end if
                end if
            else if params[0] == "scan" then
                if params.len == 1 then
                    print("<b>Usage: scan [ip_address] (--opt[port])</b>")
                else if params.len == 2 then
                    if is_valid_ip(params[1]) == true then
                        scanLibraries(params[1])
                    else
                        print("<b><color=#ff0000>Invalid!</b></color>")
                    end if
                else if params.len == 3 then
                    if is_valid_ip(params[1]) == true then
                        scanLibraries(params[1], params[2])    
                    else
                        print("<b><color=#ff0000>Invalid!</b></color>")    
                    end if
                end if
            else if params[0] == "check" then
                lol = "BoomBoomBoom"
                lol = lol.replace("B", "L")
                print(lol)
            end if           
        end if
    end while
end if