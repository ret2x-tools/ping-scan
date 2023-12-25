#!/usr/bin/env python3

# Author: Bryan Muñoz (ret2x)

import argparse
import ipaddress
from queue import Queue
from scapy.all import *
import signal
import sys
import threading
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


class HostDiscovery:
    def __init__(self, subnet, n_threads):
        self.__subnet = subnet
        self.__network = ipaddress.ip_network(self.__subnet, strict=False)
        self.__print_lock = threading.Lock()
        self.__q = Queue()
        self.__n_threads = n_threads

    def __ping(self):
        while True:
            ip = self.__q.get()

            icmp = IP(dst=str(ip))/ICMP()
            resp = sr1(icmp, timeout=2, verbose=0)

            if resp is not None:
                with self.__print_lock:
                    print(f"Host {str(ip):13} is up")

            self.__q.task_done()

    def ping_scan(self):
        for ip in self.__network.hosts():
            self.__q.put(ip)

        for t in range(self.__n_threads):
            worker = threading.Thread(target=self.__ping, daemon=True)
            worker.start()

        self.__q.join()


def signal_handler(signum, frame):
    sys.exit()


signal.signal(signal.SIGINT, signal_handler)


def main():
    parser = argparse.ArgumentParser(description="Host Discovery",
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     epilog="Example: \n"
                                     "ping-scan.py -r 192.168.1.0/24")
    parser.add_argument("-r", dest="subnet", metavar="RANGE",
                        help="subnet range (e.g. 192.168.1.0/24)")
    parser.add_argument("-t", dest="threads", metavar="THREADS",
                        default=50, type=int, help="default 50")
    args = parser.parse_args()

    if args.subnet:
        scan = HostDiscovery(args.subnet, args.threads)
        scan.ping_scan()

    else:
        sys.exit()


if __name__ == "__main__":
    main()
