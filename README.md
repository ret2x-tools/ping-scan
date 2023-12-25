# ping-scan

ping-scan is a tool that sends ICMP echo requests to discover active hosts on a local network.

## Installation

```
git clone https://github.com/ret2x-tools/ping-scan.git
pip install -r requirements.txt
```

## Usage

```
root@parrot:~$ python3 ping-scan.py -h
usage: ping-scan.py [-h] [-r RANGE] [-t THREADS]

Host Discovery

optional arguments:
  -h, --help  show this help message and exit
  -r RANGE    subnet range (e.g. 192.168.1.0/24)
  -t THREADS  default 50

Example: 
ping-scan.py -r 192.168.1.0/24
```
