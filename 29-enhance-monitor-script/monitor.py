#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import sys
import glob

PROC_FILE = {
    'tcp': '/proc/net/tcp',
    'tcp6': '/proc/net/tcp6',
    'udp': '/proc/net/udp',
    'udp6': '/proc/net/udp6'
}

STATUS = {
    '01': 'ESTABLISHED',
    '02': 'SYN_SENT',
    '03': 'SYN_RECV',
    '04': 'FIN_WAIT1',
    '05': 'FIN_WAIT2',
    '06': 'TIME_WAIT',
    '07': 'CLOSE',
    '08': 'CLOSE_WAIT',
    '09': 'LAST_ACK',
    '0A': 'LISTEN',
    '0B': 'CLOSING'
}


def get_content(type):
    with open(PROC_FILE[type], 'r') as file:
        content = file.readlines()
        content.pop(0)
    return content


def get_program_name(pid):
    path = '/proc/' + str(pid) + '/comm'
    with open(path, 'r') as file:
        content = file.read()
    content = content.strip()
    return content


def convert_ip_port(ip_port):
    ip, port = ip_port.split(':')
    port = int(port, 16)
    ip = [str(int(ip[6:8], 16)), str(int(ip[4:6], 16)), str(int(ip[2:4], 16)),
          str(int(ip[0:2], 16))]
    ip = '.'.join(ip)
    return ip, port


def main(choose):
    content = get_content(choose)
    info_list = [info.split() for info in content]
    pids = {iterms_list[9]: None for iterms_list in info_list}
    for path in glob.glob('/proc/[1-9]*/fd/[1-9]*'):
        try:
            match = re.findall('(socket|pipe):\[(\d+)\]', os.readlink(path))
            if match and match[0][1] in pids:
                pids[match[0][1]] = int(path.split('/')[2])
        except:
            pass
    for iterms_list in info_list:
        proto = choose
        local_address = "%s:%s" % convert_ip_port(iterms_list[1])
        status = STATUS[iterms_list[3]]
        if status == 'LISTEN':
            remote_address = '-'
        else:
            remote_address = "%s:%s" % convert_ip_port(iterms_list[2])
        pid = pids[iterms_list[9]]
        program_name = ''
        if pid:
            program_name = get_program_name(pid)
        print(templ % (
            proto,
            local_address,
            remote_address,
            status,
            pid or '-',
            program_name or '-',
        ))


if __name__ == '__main__':
    choose = 'all'
    if len(sys.argv) > 1:
        choose = sys.argv[1]
    templ = "%-5s %-30s %-30s %-13s %-6s %s"
    print(templ % (
        "Proto", "Local address", "Remote address", "Status", "PID",
        "Program name"))
    if choose == "all":
        for k in PROC_FILE:
            main(k)
    else:
        main(choose)
