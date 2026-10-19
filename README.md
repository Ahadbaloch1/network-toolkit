# NetTool: Network Toolkit in Python

A small command-line toolkit for network engineers and students. It covers everyday networking tasks: subnet calculation, VLSM planning, port scanning, host discovery, DNS lookups, and banner grabbing.

It uses only the Python standard library, so there is nothing to install.

## Features

| Command  | Description |
|----------|-------------|
| `subnet` | IPv4 subnet calculator (network, mask, wildcard, broadcast, host range) with optional splitting |
| `vlsm`   | Variable Length Subnet Mask planner that allocates subnets for given host counts |
| `scan`   | Multi-threaded TCP port scanner with service names |
| `sweep`  | TCP-based host discovery for a network range |
| `dns`    | Forward and reverse DNS lookup |
| `banner` | Grab a service banner from an open port |

## Requirements

- Python 3.8 or later

## Usage

```bash
# Subnet calculator, split into /26 subnets
python3 nettool.py subnet 192.168.10.0/24 --split 26

# VLSM plan for subnets needing 100, 50, 20 and 2 hosts
python3 nettool.py vlsm 192.168.10.0/24 --hosts 100 50 20 2

# Scan common ports on a host
python3 nettool.py scan 192.168.1.1 --ports 22,80,443,8000-8100

# Find live hosts in a network
python3 nettool.py sweep 192.168.1.0/24

# DNS lookup
python3 nettool.py dns example.com

# Grab a banner
python3 nettool.py banner 192.168.1.10 22
```

## Example output

```
$ python3 nettool.py vlsm 192.168.10.0/24 --hosts 100 50 20 2
Hosts      Network              Netmask          Usable
100        192.168.10.0/25      255.255.255.128  126
50         192.168.10.128/26    255.255.255.192  62
20         192.168.10.192/27    255.255.255.224  30
2          192.168.10.224/30    255.255.255.252  2
```

## Running the tests

```bash
python3 -m unittest discover -s tests -v
```

The tests cover subnet math, VLSM allocation, port parsing, and the scanner (using a local test server).

## How it works

- **Subnetting and VLSM** use Python's `ipaddress` module. VLSM sorts the requests from largest to smallest, calculates the host bits needed (hosts + network + broadcast), and aligns each block to its size boundary so subnets never overlap.
- **Port scanning** opens TCP connections in parallel using a thread pool.
- **Host discovery** uses TCP connections instead of ICMP, so it works without administrator rights. A host counts as alive if a port accepts the connection or actively refuses it.

## Limitations

- IPv4 only for subnetting and sweeping.
- Sweeps are limited to 1024 hosts per run.
- TCP-only scanning; there is no UDP or ICMP support.

## Legal and ethical use

Only scan networks and systems that you own or have written permission to test. Unauthorized scanning may be illegal.

## Possible improvements

- IPv6 support
- Export results to JSON or CSV
- ICMP ping and traceroute
- Service version detection

## License

MIT License. See the `LICENSE` file.
