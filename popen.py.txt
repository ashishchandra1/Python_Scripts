import subprocess
option="/etc/resolv.conf"
parameter="-l"

p = subprocess.Popen(["ls", parameter, option], stdout=subprocess.PIPE)

output, err = p.communicate()

print "*** Running ls -l command ***\n", output

=======================================================================================================================

#This will keep on flushing the output on console

import subprocess
cmdping = "ping -c 10 www.google.com"
p = subprocess.Popen(cmdping, shell=True, stderr=subprocess.PIPE)
while True:
    out = p.stderr.read(1)
    if out == '' and p.poll() != None:
        break
    if out != '':
        sys.stdout.write(out)
        sys.stdout.flush()
        
        


***************************
Block Access To Outgoing IP TCP / UDP Port Number

It is also possible to block specific port numbers. For example, you can block tcp port # 5050 as follows:
iptables -A OUTPUT -p tcp –dport 5050 -j DROP

To block tcp port # 5050 for an IP address 192.168.1.2 only, enter:
iptables -A OUTPUT -p tcp -d 192.168.1.2 –dport 5050 -j DROP

Finally, you need to save your firewall rules. Under CentOS / RHEL / Fedora Linux, enter:
# /sbin/service iptables save
