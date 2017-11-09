Linux Process Hunter
=================

**I wrote prochunter around 2002, after the SuckIT rootkit release by sd [4], I just spent few hours to make it runnable on modern kernels (tested on 4.x)**

Prochunter aims to find hidden process with all userspace and most of the kernelspace rootkits.
This tool is composed of a kernel module that prints out all running processes walking the task_struct list and creates /sys/kernel/proc_hunter/set entry. A python script that 
invokes
the kernel function and diffs the module output with processes list collected from userspace (/proc walking).

Almost all public linux kernel rootkits try to hide processes via /proc VFS to remove the hidden processes from ps/top/etc. output.
Others use the trick to change the evil process pid to 0 (but the exit call will panic the kernel) [1]

As far as I know only adore-ng, fuuld and some not working PoC from academic papers use DKOM (in particular: unlink process from task_struct/pidhash lists) [2]  [3]

(Un)fortunately latters are stable only on kernel 2.4.x schedulers like SCHED_FIFO or SCHED_RR, because scheduler doesn't rely on task_struct or pidhash list to make a context switch
amoung the processes, when CFS scheduler algorithm (default on linux now) was introduced with 2.6 all those rootkits have become very unusable, but..;p

----------


Compilation
-------------

The python script requires python3 and psutil.

The kernel module just needs the kernel headers.

    make


How to use
-------------

    $ ./prochunter.py 
    usage: prochunter.py [-h] [--ps] [--pstree] [-p] [-d] [-r] [-S hostname]
    
    optional arguments:
    -h, --help   show this help message and exit
    --ps         Print process list from kmod.
    --pstree     Print process tree from kmod.
    -p           Install prochunter in persistence mode (/sys entry created).
    -d           Run process list diff when in persistence mode.
    -r           Run process list diff once.
    -S hostname  remote syslog server
    
     
    
     - Print running process including the hidden processes. :)
     sudo ./prochunter.py --ps
    
     - Print running process tree
     sudo ./prochunter --pstree

     - Install the module in persistence mode.
    sudo ./prochunter.py -p 
    
     - Invoke prochunter via /sys and show hidden processes (if any), useful with cron.
    sudo ./prochunter.py -d
    
    - Invoke prochunter via /sys and show hidden processes and send logs to a remote syslog server.
    sudo ./prochunter.py -d -S 10.0.0.2
    
     - Run prochunter without persistence.
    sudo ./prochunter.py -r
    

Example
-------------

I wrote an easy example of kernel module that hides sshd process as pid 0, chkrootkit was not able to find it.

    $ ./chkrootkit 
    ROOTDIR is `/'
    Checking `amd'... not found
    Checking `basename'... not infected
    Checking `biff'... not found
    Checking `chfn'... not infected
    [...]
    Checking `rlogind'... not infected
    Checking `rshd'... not found
    Checking `slogin'... not found
    Checking `sendmail'... not found
    Checking `sshd'... /usr/bin/strings: Warning: '/' is a directory
    not infected
    [...]
    Searching for suspect PHP files... nothing found
    Searching for anomalies in shell history files... nothing found
    Checking `asp'... not infected
    Checking `bindshell'... not infected
    Checking `lkm'... chkproc: nothing detected
    chkdirs: nothing detected
    [...]
    chkutmp: nothing deleted
    
    
    this is with prochunter
    
    $ sudo ./prochunter.py -r
    
    [!] Found 1 hidden process
    
    PID	Name
    0	sshd



    
[1] http://phrack.org/issues/63/18.html#article

[2] https://www.blackhat.com/presentations/win-usa-04/bh-win-04-butler.pdf

[3] http://phrack.org/issues/61/14.html

[4] http://phrack.org/issues/58/7.html


