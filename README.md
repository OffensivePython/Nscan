# Nscan
Nscan is a fast Network scanner optimized for internet-wide scanning purposes and inspired by Masscan and Zmap. It has it's own tiny TCP/IP stack and uses Raw sockets to send TCP SYN probes. It doesn't need to set SYN Cookies so it doesn't wastes time checking if a received packet is a result of it's own scan, that makes Nscan faster than other similar scanners.

Nscan has a cool feature that allows you to extend your scan by chaining found ip:port to another scripts where they might check for vulnerabilities, exploit targets, look for Proxies/VPNs... 

Nscan is a free tool, but consider donating here: 1Gi5Rpz5RBEUpGknSwyRgqzk7b5bQ7Abp2

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
Nscan is simple to use, it works just the way you expect.

If this your first run, you need to load nscan alias interface before launching a Scan
```
$ ./nscan.py iface load
Press enter key to load nscan alias interface

[....] Running /etc/init.d/networking restart is deprecated because it may not [warnable some interfaces ... (warning).
[ ok ] Reconfiguring network interfaces...done.
Nscan alias interface loaded: 10.0.2.16
```
Simple Scan:
-----------
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

Scanning [192.168.0.0 -> 192.169.0.0] (65536 hosts/2 ports)
[MAIN] Starting the scan (Fri Jan 30 07:11:02 2015)
...
```
This scans the 65536 hosts in your local network
Scanning the Entire Internet:
----------------------------
Scan the entire IPv4 address space for port 80
```
$ ./nscan.py 0.0.0.0/0 -p80
```

Multithreading the scan:
-----------------------
use '-t' to specify how many sending thread you want to use, it decreases the elapsed time of the scan by n times:
```
$ ./nscan.py 192.168.0.0/16 -p3389,5900-5910 -t3 
```
This splits the 65536 hosts in 3 ranges (3 threads), every thread is going to scan 21845 host

Grabbing banners and saving logs in a file:
----------------------------------------
use '-b' to grab banners and '-o' to save logs in a file
```
$ ./nscan.py 192.168.0.0/16 -p3389,5900-5910 -t3 -b -o nscan.log
```

Scanning to find N results:
----------------------------
In order to stop the scan after receiving 10 results:
```
$ ./nscan.py 192.168.0.0/16 -p443 -b -n10
```

Importing Nscripts:
-------------------
To import Nscripts, use '--import' with filename (without extension '.py') and specify the port and/or range of ports
```
$ ./nscan.py xxx.xxx.161.152/24 -p1080 --import=proxy:1080

    _   __                    
   / | / /_____________ _____ 
  /  |/ / ___/ ___/ __ `/ __ \
 / /|  (__  ) /__/ /_/ / / / /
/_/ |_/____/\___/\__,_/_/ /_/ 
@OffensivePython             1.0
URL: https://github.com/OffensivePython/Nscan

Scanning [xxx.xxx.161.152 -> xxx.xxx.162.0] (104 hosts/1 ports)
[MAIN] Starting the scan (Fri Jan 30 09:14:14 2015)
[SEND] Sent: 104 packets
[RECV] Received: 7 packets
[MAIN] xxx.xxx.161.152:1080
[MAIN] xxx.xxx.161.173:1080
[MAIN] xxx.xxx.161.195:1080
[MAIN] xxx.xxx.161.196:1080
[MAIN] xxx.xxx.161.194:1080
[MAIN] xxx.xxx.161.239:1080
[MAIN] xxx.xxx.161.193:1080
[PROXY] xxx.xxx.161.152:1080 | SOCKS4
[PROXY] xxx.xxx.161.195:1080 | SOCKS4
[PROXY] xxx.xxx.161.196:1080 | SOCKS4
[PROXY] xxx.xxx.161.194:1080 | SOCKS4
[PROXY] xxx.xxx.161.193:1080 | SOCKS4
[MAIN] Packets sent in 0.0 minutes
[MAIN] Total elapsed time: 0.7 minutes
[MAIN] Done (Fri Jan 30 09:14:58 2015)
```
Every ip has the port 1080 open, will be chained to the Nscript proxy, which checks if a SOCKS service is running behind it.

This will chain every ip:port that has the port 1080,3127,3128,3129 open:
```
$ ./nscan.py xxx.xxx.xxx.xxx/xx -p8080,1080,3127-3129 --import=proxy:1080,3127-3129
```
P.S: Port 8080 will not be chained to the script, since it's not specified

Suspending/Resuming a Scan:
---------------------------
If you have a large range of hosts to scan, and your bandwidth can't finish the scan really quick, You can suspend a scan and resume it later where it's stopped.

To suspend a running scan, hit [CTRL]+C, Nscan will save where it's paused in 'resume.conf'.
The resume configuration file looks something like this:
```
$ cat resume.conf
[NSCAN]
hosts = [167772160, 184549376L]
ports = [[80, 81]]
threads = 1
imports = None
banner = True
count = None
output = None
indexes = [(16777216L, 4194304L, -249, 16776967L, 249)]
cooldown = (1000, 1.0)
```
To resume a previous scan, simply type:
```
$ ./nscan.py resume resume.conf
```

Cooling Down the Transfer rate:
-------------------------------
This is a very important option to regulate Nscan with your bandwidth, If you don't choose this properly, Nscan will probably knock off your router and force it to restart since it sends more traffic than your router could handle.
You can specify the number of packets that needs to be sent before Nscan should cool down and sleep for a while
```
$ ./nscan.py 10.0.0.0./16 -p21-25,8080 --cooldown=100,0.1
```
This tells Nscan, "for every 100 packets sent, sleep for 0.1 second(s)"
P.S: The size of one packet is 54 bytes

If you have a gigabit Ethernet connection, you probably want to disable this:
```
$ ./nscan.py 0.0.0.0./0 -p21-25,8080 --cooldown=[ANY],0
```

# Write your Own Nscripts
Every nscan script should have a run() function, that takes two arguments:

queue: queue where your script receives ip:port

event: This tells your script that Nscan is completed the scan, and waiting for your script to finsish before it exits

Make sure that your script is under '~/nscan/nscripts' folder.

Every Nscript has this simple skeleton:
```Python
import Queue
import logging
# Import any module you need here

def run(queue, event):
    while True:
        if queue.empty() and event.isSet():
            # If the Scan is completed and the queue is empty (no more results)
            break
        else:
            try:
                ip, port = queue.get(False, TIMEOUT) # Should be non-blocking
                # Do something useful with IP:PORT
            except KeyboardInterrupt: # Scan suspended, should exit
                break
            except Queue.Empty: # No results
                pass
                
```
Use the logging module to output your results:
```
SCRIPT = 'MYSCRIPT'
logging.info('[{}] {}:{} | {}'.format(SCRIPT, IP, PORT, 'MY RESULTS'))
```

# Contribute and Share you Nscripts:
Tips, Requests, Improvements to make Nscan more stable and faster are always welcome.

If you want to share your Nscripts with everybody, tweet me at @OffensivePython #Nscan with a link of your script, and i will add it under the nscript folder here
