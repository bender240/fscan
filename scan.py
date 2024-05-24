import nmap

nm = nmap.PortScanner()
userInt = int(input("1. fastScan 2. fullScan: "))
userintTarget = input("Target: ")
target = userintTarget
options = "-A -P -T4"

if userInt == 1:
    nm.scan(target)
else:
    nm.scan(target, arguments=options)

for host in nm.all_hosts():
    print("Host: ", host)
    print("State: ", nm[host].state())
    for proto in nm[host].all_protocols():
        print("Protocol: ", proto)
        ports = nm[host][proto].keys()
        for port in ports:
            print("Port: ", port, "State: ", nm[host][proto][port]['state'])
