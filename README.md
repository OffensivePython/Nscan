# Nscan
Nscan is a fast Network scanner optimized for internet-wide scanning purposes inspired by Masscan and Zmap. It has it's own tiny TCP/IP stack and uses Raw sockets for sending TCP SYN probes. It doesn't need to set SYN Cookies so it doesn't wastes time checking if a received packet is a result of it's own scan, that makes Nscan faster than other similar scanners.

Nscan has a cool feature which allow you to extend your scan by chaining found ip:port to another scripts where it might checks for vulnerabilities, exploit targets, check for Proxies/VPNs... 

# Getting Nscan to work

Installing Nscan on Debian/Ubuntu boxes:
```
$ git clone https://github.com/OffensivePython/Nscan
$ cd Nscan/nscan
$ chmod +x nscan.py
```

Check if Nscan executes
```
$ ./nscan.py
Usage: 
nscan.py x.x.x.x/x [options]
nscan.py iface load/unload : Load/Unload Nscan alias interface
nscan.py resume filename.conf: resume previous scan


Options:
  -h, --help            show this help message and exit
  -p PORTS, --port=PORTS
                        Port(s) number (e.g. -p21-25,80)
  -t THREADS, --threads=THREADS
                        Threads used to send packets (default=1)
  --import=IMPORTS      Nscan scripts to import (e.g.
                        --import=ssh_key:22+check_proxy:80-85,8080)
  -b, --banner          Fetch banners
  -n COUNT              Number of results to get
  -o FILE, --output=FILE
                        Output file
  -c N,T, --cooldown=N,T
                        Every N (int) packets sent sleep P (float)
                        (Default=1000,1)
```

# Usage
First thing you need to do is to load nscan alias interface
```
$ ./nscan.py iface load
Press enter key to load nscan alias interface

[....] Running /etc/init.d/networking restart is deprecated because it may not [warnable some interfaces ... (warning).
[ ok ] Reconfiguring network interfaces...done.
Nscan alias interface loaded: 10.0.2.16
```
# Simple Scan
To scan your local network for port 22,80:
```
$ ./nscan.py 192.168.0.0/16 -p22,80

    _   __                    
   / | / /_____________ _____ 
  /  |/ / ___/ ___/ __ `/ __ \
 / /|  (__  ) /__/ /_/ / / / /
/_/ |_/____/\___/\__,_/_/ /_/ 
@OffensivePython             1.0
URL: https://github.com/OffensivePython/Nscan

Scanning [192.168.0.0 -> 192.169.0.0] (65536 hosts/1 ports)
[MAIN] Starting the scan (Fri Jan 30 07:11:02 2015)
...
```
This scans your 65535 hosts in your local network

Multithreading the scan:
-----------------------
```
$ ./nscan.py 192.168.0.0/16 -p3389,5900-5910 -t3 
```
This splits the 65535 hosts in 3 ranges (3 threads), every thread is going to scan 21845 host

Grabbing banners and save logs in a file:
----------------------------------------
```
$ ./nscan.py 192.168.0.0/16 -p3389,5900-5910 -t3 -b -o nscan.log
```

Scanning to find 10 results:
----------------------------
```
$ ./nscan.py 192.168.0.0/16 -p443 -b -n10
```

