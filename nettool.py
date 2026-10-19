#!/usr/bin/env python3
"""NetTool: a small command-line toolkit for network engineers and students.

Features:
  subnet  - IPv4 subnet calculator (with optional splitting)
  vlsm    - Variable Length Subnet Mask planner
  scan    - Multi-threaded TCP port scanner
  sweep   - TCP-based host discovery for a network range
  dns     - Forward and reverse DNS lookup
  banner  - Grab a service banner from an open port

Only the Python standard library is used.
Use the scanning features only on systems you own or have permission to test.
"""

import argparse
import ipaddress
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

MAX_SWEEP_HOSTS = 1024


# ---------------------------------------------------------------------------
# Subnetting
# ---------------------------------------------------------------------------
def _ipv4_network(cidr):
    net = ipaddress.ip_network(cidr, strict=False)
    if net.version != 4:
        raise ValueError("Only IPv4 networks are supported.")
    return net


def subnet_info(cidr):
    """Return a dictionary describing an IPv4 network."""
    net = _ipv4_network(cidr)
    if net.prefixlen <= 30:
        usable = net.num_addresses - 2
        first = net.network_address + 1
        last = net.broadcast_address - 1
        broadcast = str(net.broadcast_address)
    elif net.prefixlen == 31:
        usable = 2
        first, last = net.network_address, net.broadcast_address
        broadcast = "n/a (point-to-point /31)"
    else:
        usable = 1
        first = last = net.network_address
        broadcast = "n/a (single host /32)"
    return {
        "network": str(net.network_address),
        "prefix": net.prefixlen,
        "netmask": str(net.netmask),
        "wildcard": str(net.hostmask),
        "broadcast": broadcast,
        "first_host": str(first),
        "last_host": str(last),
        "total_addresses": net.num_addresses,
        "usable_hosts": usable,
        "is_private": net.is_private,
    }


def split_subnet(cidr, new_prefix):
    """Split a network into smaller subnets of the given prefix length."""
    net = _ipv4_network(cidr)
    if new_prefix <= net.prefixlen or new_prefix > 32:
        raise ValueError("New prefix must be longer than %d and at most 32." % net.prefixlen)
    return [str(s) for s in net.subnets(new_prefix=new_prefix)]


def vlsm_plan(cidr, host_counts):
    """Allocate subnets for the requested host counts (largest first).

    Returns a list of dictionaries with the requested hosts, the allocated
    network, the netmask, and the number of usable hosts.
    """
    net = _ipv4_network(cidr)
    start = int(net.network_address)
    end = int(net.broadcast_address)
    current = start
    plan = []
    for hosts in sorted(host_counts, reverse=True):
        if hosts < 1:
            raise ValueError("Each subnet needs at least 1 host.")
        bits = (hosts + 2 - 1).bit_length()  # host bits needed incl. network+broadcast
        size = 2 ** bits
        current = (current + size - 1) // size * size  # align to block size
        if current + size - 1 > end:
            raise ValueError("Not enough address space in %s for the requested hosts." % cidr)
        sub = ipaddress.ip_network((current, 32 - bits))
        plan.append({
            "requested_hosts": hosts,
            "network": str(sub),
            "netmask": str(sub.netmask),
            "usable_hosts": size - 2,
        })
        current += size
    return plan


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------
def parse_ports(spec):
    """Parse a port specification such as '22,80,8000-8100' into a sorted list."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            low, high = part.split("-", 1)
            low, high = int(low), int(high)
            if low > high:
                raise ValueError("Invalid port range: %s" % part)
            ports.update(range(low, high + 1))
        else:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("Ports must be between 1 and 65535.")
    return sorted(ports)


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def is_port_open(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_ports(host, ports, timeout=1.0, workers=100):
    """Return a sorted list of open TCP ports on the host."""
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: (p, is_port_open(host, p, timeout)), ports)
    return sorted(p for p, ok in results if ok)


def is_host_alive(host, ports=(80, 443, 22), timeout=1.0):
    """A host is considered alive if a port accepts or actively refuses a connection."""
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except ConnectionRefusedError:
            return True
        except OSError:
            continue
    return False


def sweep(cidr, ports=(80, 443, 22), timeout=1.0, workers=100):
    net = _ipv4_network(cidr)
    hosts = [str(h) for h in net.hosts()] or [str(net.network_address)]
    if len(hosts) > MAX_SWEEP_HOSTS:
        raise ValueError("Range too large (max %d hosts)." % MAX_SWEEP_HOSTS)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda h: (h, is_host_alive(h, ports, timeout)), hosts)
    return [h for h, alive in results if alive]


# ---------------------------------------------------------------------------
# DNS and banners
# ---------------------------------------------------------------------------
def dns_lookup(name):
    """Resolve a hostname or IP address. Returns a dictionary of results."""
    result = {"query": name, "addresses": [], "hostname": None}
    try:
        ipaddress.ip_address(name)
        result["hostname"] = socket.gethostbyaddr(name)[0]
        result["addresses"] = [name]
    except ValueError:
        infos = socket.getaddrinfo(name, None)
        result["addresses"] = sorted({i[4][0] for i in infos})
    return result


def grab_banner(host, port, timeout=2.0):
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        try:
            return s.recv(1024).decode(errors="replace").strip()
        except socket.timeout:
            return ""


# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(prog="nettool", description="Network toolkit")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("subnet", help="IPv4 subnet calculator")
    s.add_argument("cidr", help="Network in CIDR notation, e.g. 192.168.1.0/24")
    s.add_argument("--split", type=int, metavar="PREFIX", help="Split into subnets of this prefix length")

    v = sub.add_parser("vlsm", help="VLSM planner")
    v.add_argument("cidr")
    v.add_argument("--hosts", type=int, nargs="+", required=True, help="Host counts, e.g. 100 50 20")

    sc = sub.add_parser("scan", help="TCP port scanner")
    sc.add_argument("host")
    sc.add_argument("--ports", default="1-1024", help="e.g. 22,80,443 or 1-1024")
    sc.add_argument("--timeout", type=float, default=1.0)

    sw = sub.add_parser("sweep", help="TCP host discovery")
    sw.add_argument("cidr")
    sw.add_argument("--ports", default="80,443,22")
    sw.add_argument("--timeout", type=float, default=1.0)

    d = sub.add_parser("dns", help="DNS lookup")
    d.add_argument("name")

    b = sub.add_parser("banner", help="Grab a service banner")
    b.add_argument("host")
    b.add_argument("port", type=int)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "subnet":
            for key, value in subnet_info(args.cidr).items():
                print("%-16s %s" % (key + ":", value))
            if args.split:
                print("\nSubnets:")
                for s in split_subnet(args.cidr, args.split):
                    print("  " + s)
        elif args.command == "vlsm":
            print("%-10s %-20s %-16s %s" % ("Hosts", "Network", "Netmask", "Usable"))
            for row in vlsm_plan(args.cidr, args.hosts):
                print("%-10d %-20s %-16s %d" % (row["requested_hosts"], row["network"],
                                               row["netmask"], row["usable_hosts"]))
        elif args.command == "scan":
            open_ports = scan_ports(args.host, parse_ports(args.ports), args.timeout)
            if open_ports:
                print("Open ports on %s:" % args.host)
                for port in open_ports:
                    print("  %-6d %s" % (port, service_name(port)))
            else:
                print("No open ports found on %s." % args.host)
        elif args.command == "sweep":
            alive = sweep(args.cidr, tuple(parse_ports(args.ports)), args.timeout)
            print("%d host(s) responded:" % len(alive))
            for host in alive:
                print("  " + host)
        elif args.command == "dns":
            info = dns_lookup(args.name)
            if info["hostname"]:
                print("Hostname: %s" % info["hostname"])
            for addr in info["addresses"]:
                print("Address:  %s" % addr)
        elif args.command == "banner":
            banner = grab_banner(args.host, args.port)
            print(banner or "(no banner received)")
    except (ValueError, OSError) as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
