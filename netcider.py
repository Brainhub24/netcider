#!/usr/bin/env python3

"""
Codename  : Netcider
Version   : v2.0 Beta
Scriptname: netcider.py

This script calculates and displays various network-related information for a given IP address and subnet mask
in CIDR (Classless Inter-Domain Routing) notation.

It provides the following information:
- Base: The network address or network ID of the subnet.
- Netmask: The subnet mask associated with the CIDR notation.
- Wildcard: The wildcard mask, which is the inverse of the subnet mask.
- Broadcast: The broadcast address for the subnet.
- Subnet ID: The lowest address in the subnet.
- Host min: The lowest assignable IP address in the subnet.
- Host max: The highest assignable IP address in the subnet.
- Total Hosts: The total number of assignable IP addresses in the subnet.

Author      :  Shawn Evans (sevans@nopsec.com)
Constributor:  Jan Gebser  (github@brainhub24.com)

"""

import sys
import operator
import itertools
from functools import reduce
from prettytable import PrettyTable
from rich.console import Console
from rich.table import Table
from rich import print as rich_print

class CIDR:

    def __init__(self, address):
        try:
            index = address.index('/')
            self.base = address[:index]
            intMask = address[index+1:]
            self.netmask = self.calculate_netmask(intMask)
            self.wildcard = self.calculate_wildcard(intMask)
            self.binBase = self.address_to_bin(self.base)
            self.subnet = self.list_to_string(self.network(self.base, self.netmask))
            self.hostmin = self.host_min(self.subnet)
            self.hostmax = self.host_max(self.subnet, self.wildcard)
            self.total = self.num_hosts(self.wildcard)
            self.broadcast = self.host_min(self.hostmax)
            self.allips = self.get_ip_list(self.hostmin, self.hostmax)
        except Exception as e:
            print(e)

    def update(self, address):
        try:
            index = address.index('/')
            self.base = address[:index]
            intMask = address[index+1:]
            self.netmask = self.calculate_netmask(intMask)
            self.wildcard = self.calculate_wildcard(intMask)
            self.binBase = self.address_to_bin(self.base)
            self.subnet = self.list_to_string(self.network(self.base, self.netmask))
            self.hostmin = self.host_min(self.subnet)
            self.hostmax = self.host_max(self.subnet, self.wildcard)
            self.total = self.num_hosts(self.wildcard)
            self.broadcast = self.host_min(self.hostmax)
            self.allips = self.get_ip_list(self.hostmin, self.hostmax)
        except Exception as e:
            print(e)

    def __str__(self):
        if len(sys.argv) > 1:
            table = PrettyTable()
            table.field_names = ["Property", "Value"]
            table.align["Property"] = "l"
            table.align["Value"] = "l"
            table.add_row([f"\033[94mBase\033[0m", self.base])
            table.add_row([f"\033[94mNetmask\033[0m", self.netmask])
            table.add_row([f"\033[94mWildcard\033[0m", self.wildcard])
            table.add_row([f"\033[94mBroadcast\033[0m", self.broadcast])
            table.add_row([f"\033[94mSubnet ID\033[0m", self.subnet])
            table.add_row([f"\033[94mHost min\033[0m", self.hostmin])
            table.add_row([f"\033[94mHost max\033[0m", self.hostmax])
            table.add_row([f"\033[94mTotal Hosts\033[0m", str(self.total)])
            return str(table)
        else:
            table = Table(title="Network Information")
            table.add_column(f"[blue]Property[/blue]")
            table.add_column(f"[green]Value[/green]")
            table.add_row("Base", self.base)
            table.add_row("Netmask", self.netmask)
            table.add_row("Wildcard", self.wildcard)
            table.add_row("Broadcast", self.broadcast)
            table.add_row("Subnet ID", self.subnet)
            table.add_row("Host min", self.hostmin)
            table.add_row("Host max", self.hostmax)
            table.add_row("Total Hosts", str(self.total))
            return str(table)

    def get_ip_list(self, hostmin, hostmax):
        tmpmin = hostmin.split('.')
        tmpmax = hostmax.split('.')
        ranges = [range(i, j + 1) for i, j in zip(list(map(int, tmpmin)), list(map(int, tmpmax)))]
        complete = []
        for ip in itertools.product(*ranges):
            complete.append('.'.join(list(map(str, list(ip)))))
        return complete

    def num_hosts(self, wildcard):
        tmpWild = list(map(int, wildcard.split('.')))
        ranges = list(map(lambda e: len(range(0, e + 1)), tmpWild))
        numhosts = reduce(operator.mul, ranges)
        return numhosts if numhosts > 0 else 1

    def host_min(self, address):
        temp = address.split('.')
        temp[3] = str(int(temp[3]))
        return self.list_to_string(temp)

    def host_max(self, address, wildcard):
        tmpAddr = address.split('.')
        tmpWild = wildcard.split('.')
        tmpWild[3] = str(int(tmpWild[3]))
        return self.list_to_string(list(map(sum, zip(list(map(int, tmpAddr)), list(map(int, tmpWild))))))

    def calculate_netmask(self, mask):
        binMask = '%s%s' % ('1'*int(mask), '0'*(32-int(mask)))
        maskList = list(map(''.join, zip(*[iter(binMask)] * 8)))
        netmask = self.bin_to_address(maskList)
        return self.list_to_string(netmask)

    def calculate_wildcard(self, mask):
        binMask = '%s%s' % ('1'*int(mask), '0'*(32-int(mask)))
        maskList = list(map(''.join, zip(*[iter(binMask)] * 8)))
        netmask = self.bin_to_address(maskList)
        wildcard = [255 - val for val in netmask]
        return self.list_to_string(wildcard)

    @staticmethod
    def list_to_string(ipList):
        return '.'.join(map(str, ipList))

    def network(self, address, netmask):
        binNetwork = [bin(int(a, 2) & int(b, 2))[2:].zfill(8) for a, b in zip(self.address_to_bin(address), self.address_to_bin(netmask))]
        return self.bin_to_address(binNetwork)

    @staticmethod
    def address_to_bin(address):
        return [bin(int(val))[2:].zfill(8) for val in address.split('.')]

    @staticmethod
    def bin_to_address(binAddress):
        return [int(val, 2) for val in binAddress]

def usage():
    title = 'Netcider v2.0 Beta'
    author_0x01 = 'Shawn Evans'
    email_0x01 = 'sevans@nopsec.com'
    author_0x02 = 'Jan Gebser'
    email_0x02 = 'github@brainhub24.com'
    console = Console()
    console.rule("Netcider v2.0 Beta", style="magenta")
    console.print(f"Author      :  [cyan]{author_0x01}[/cyan] ([cyan]{email_0x01}[/cyan])")
    console.print(f"Constributor:  [cyan]{author_0x02}[/cyan]  ([cyan]{email_0x02}[/cyan])")
    console.print("\nOptions:")
    console.print("-o\tOutput full IP range to stdout")
    console.print("\nExample:")
    console.print("$ python netcider.py 192.168.0.2/24")
    console.print("$ python netcider.py -o 192.168.0.2/24")

if __name__ == '__main__':
    ipLocation = 0
    cidrIP = []

    if not sys.stdin.isatty():
        stdin_ip = sys.stdin.read().split('\n')
    else:
        ipLocation = reduce(lambda x, y: x + y, [i if (val.find('.') > 0 and val.find('/')) > 0 else 0 for i, val in enumerate(sys.argv)])

    if ipLocation > 0:
        cidrIP.append(CIDR(sys.argv[ipLocation]))
    elif not sys.stdin.isatty():
        for ip in stdin_ip:
            cidrIP.append(CIDR(ip))
    else:
        usage()
        sys.exit()

    if '-o' in sys.argv:
        for cidrItem in cidrIP:
            print(str(cidrItem))  # Call __str__ method explicitly
        sys.exit()
    else:
        for cidrItem in cidrIP:
            print(str(cidrItem))  # Call __str__ method explicitly
