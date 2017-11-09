#!/usr/bin/env python3

import sys
import collections
import os, fcntl, errno
import argparse
import logging
import logging.handlers


import psutil

KMSG = "/dev/kmsg"
KMOD_PATH="./prochunter.ko"

plist = collections.defaultdict(list)

def print_tree(parent, tree, indent=''):
    
    name = plist[parent]
    print(parent, name)
    if parent not in tree:
        return
    children = tree[parent][:-1]
    for child in children:
        sys.stdout.write(indent + "|- ")
        print_tree(child, tree, indent + "| ")
    child = tree[parent][-1]
    sys.stdout.write(indent + "`_ ")
    print_tree(child, tree, indent + "  ")


def print_procs(parent, tree, indent=''):

    print("PID\tName")
    for p in plist.items():
        print(p[0]+"\t"+p[1].pop())
    sys.exit(1)


def ko_build_tree(ph_list):

    tree = collections.defaultdict(list)
    
    for p in ph_list:
        tmp = p.split(';')
        tmp[3] = tmp[3].replace('\n', '')
        plist[tmp[2]].append(tmp[3])
        tree[tmp[1]].append(tmp[2])
    plist.pop(str(os.getpid()))
    return tree


def ps_build_tree():

    pl = collections.defaultdict(list) 
    for p in psutil.process_iter():
        pl[str(p.pid)].append(p.name()[:15])  # psutil shows the complete name, in the kernel's task_struct there is only char comm[15]
    pl.pop(str(os.getpid()))
    return pl

def ph_ko_exist():
     if os.path.exists('/sys/kernel/proc_hunter/set'):
         return 1
     else:
        return 0

def trigger_ph_ko(r):
    
    if ph_ko_exist():    
        with open('/sys/kernel/proc_hunter/set', 'w') as f:
            f.write(r)
    else:
        print("proc_hunter entry doesn't exist, check if prochunter is installed (-p).")
        sys.exit(0)
    
def build_ph_list(kmsg_path, persistence):

    import random
    r = str(random.randint(10000,99999))
    with open(kmsg_path, "r") as fp:
        #fp.flush()
        fd = fp.fileno()
        flag = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flag | os.O_NONBLOCK)

        # because python..
        for last in fp:
            pass

        fcntl.fcntl(fd, fcntl.F_SETFL, flag)
        
        # ko load
        if(persistence):
            trigger_ph_ko(r)
            rnd = r
        else:
            load_ph_ko(0)
            rnd = '31337'

        klist = []
        while True:
            line = fp.readline()
            if 'END-'+rnd in line:
                break
            else:
                klist.append(line)
        return klist 


def diff_tree(ko_tree, ps_tree):

    diff = list(set(ko_tree) - set(ps_tree))
    return diff


def load_ph_ko(persistence, r='0'):
    
    from subprocess import call
   
    if persistence:
        ret = call(["insmod", KMOD_PATH, "persistence=1", "rnd="+r])
        if(ret):
            print("insmod failed, is prochunter.ko path correct?")
    else:
        ret = call(["insmod", KMOD_PATH, "persistence=0"])
        if(ret):
            print("insmod failed, is the prochunter.ko path correct?")
            return
        ret = call(["rmmod", KMOD_PATH])
        if(ret):
            print("prochunter module is not present")



def main():
   
    parser = argparse.ArgumentParser()

    parser.add_argument('--ps', action='store_true', default=False, dest='print_ps', help='Print process list from kmod.')
    parser.add_argument('--pstree', action='store_true', default=False, dest='pstree', help='Print process tree from kmod.')
    parser.add_argument('-p', action='store_true', default=False, dest='persistence', help='Install prochunter in persistence mode (/sys entry created).')
    parser.add_argument('-d', action='store_true', default=False, dest='diff', help='Run process list diff when in persistence mode.')
    parser.add_argument('-r', action='store_true', default=False, dest='runonce', help='Run process list diff once.')
    parser.add_argument('-S', dest='syslog', metavar='hostname', required=False, help='remote syslog server')
    args = parser.parse_args()

    if(len(sys.argv) <= 1):
        parser.print_help()
        sys.exit(0)
    if(os.getuid() != 0):
        print("[x] Run prochunter as root.")
        sys.exit(0)

    if args.print_ps:
        p = 0
        if ph_ko_exist():
            p = 1
        k = build_ph_list(KMSG, p)
        t = ko_build_tree(k)
        print_procs('0', t)
        sys.exit(1)
    elif args.pstree:
        p = 0
        if ph_ko_exist():
            p = 1
        k = build_ph_list(KMSG, p)
        t = ko_build_tree(k)
        print_tree('0', t)
        sys.exit(1)
    elif args.persistence:
        load_ph_ko(1)
        sys.exit(1)
    elif args.runonce:
        k = build_ph_list(KMSG, 0)
        ko_t = ko_build_tree(k)
        ps_t = ps_build_tree()
        diff = diff_tree(plist, ps_t)
        if len(diff) > 0:
            print("\n[!] Found %d hidden process" % len(diff))
            print("\nPID\tName")
            for p in diff:
                print(p+'\t'+plist[p][0])
        else:
            print("[*] No hidden process found")
        sys.exit(1)
    elif args.diff:
        k = build_ph_list(KMSG, 1)
        ko_t = ko_build_tree(k)
        ps_t = ps_build_tree()
        print(plist)
        hidden_procs = diff_tree(plist, ps_t)
        if len(hidden_procs) > 0:
            print("\n[!] Found %d hidden process" % len(diff))
            print("\nPID\tName")
            for p in diff:
                print(p+'\t'+plist[p][0])
        else:
            print("[*] No hidden process found")
        sys.exit(1)
        if args.syslog:
            log = logging.getLogger(__name__)
            #log.setLevel(logging.DEBUG)
            handler = logging.handlers.SysLogHandler(address = (args.syslog, 514), facility=19)
            #formatter = logging.Formatter('%(module)s.%(funcName)s: %(message)s')
            #handler.setFormatter(formatter)
            log.addHandler(handler)
            log.critical(hidden_procs)
            sys.exit(1)


if __name__ == '__main__':
    main()

