import nmap

nm = nmap.PortScanner()

user_int = int(input("1. fastScan 2. fullScan: "))
target = input("Target: ")

options = ""
if user_int == 2:
    options = "-A -P -T4"

if user_int == 1:
    nm.scan(target, arguments="-F")
else:
    nm.scan(target, arguments=options + " -F")

for host in nm.all_hosts():
    print("Host: ", host)
    print("State: ", nm[host].state())
    for proto in nm[host].all_protocols():
        print("Protocol: ", proto)
        ports = list(nm[host][proto].keys())
        for port in sorted(ports):
            print("Port: ", port, "State: ", 
nm[host][proto][port]['state'])
