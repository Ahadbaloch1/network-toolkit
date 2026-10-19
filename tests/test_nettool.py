import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nettool  # noqa: E402


class SubnetTests(unittest.TestCase):
    def test_subnet_info_24(self):
        info = nettool.subnet_info("192.168.1.77/24")
        self.assertEqual(info["network"], "192.168.1.0")
        self.assertEqual(info["netmask"], "255.255.255.0")
        self.assertEqual(info["broadcast"], "192.168.1.255")
        self.assertEqual(info["first_host"], "192.168.1.1")
        self.assertEqual(info["last_host"], "192.168.1.254")
        self.assertEqual(info["usable_hosts"], 254)

    def test_subnet_info_30(self):
        self.assertEqual(nettool.subnet_info("10.0.0.0/30")["usable_hosts"], 2)

    def test_split(self):
        self.assertEqual(nettool.split_subnet("192.168.0.0/24", 26),
                         ["192.168.0.0/26", "192.168.0.64/26", "192.168.0.128/26", "192.168.0.192/26"])

    def test_split_invalid(self):
        with self.assertRaises(ValueError):
            nettool.split_subnet("192.168.0.0/24", 24)

    def test_ipv6_rejected(self):
        with self.assertRaises(ValueError):
            nettool.subnet_info("2001:db8::/32")


class VlsmTests(unittest.TestCase):
    def test_plan(self):
        plan = nettool.vlsm_plan("192.168.10.0/24", [20, 100, 50, 2])
        nets = [row["network"] for row in plan]
        self.assertEqual(nets, ["192.168.10.0/25", "192.168.10.128/26",
                                "192.168.10.192/27", "192.168.10.224/30"])

    def test_not_enough_space(self):
        with self.assertRaises(ValueError):
            nettool.vlsm_plan("192.168.10.0/25", [100, 100])


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(5)
        self.port = self.server.getsockname()[1]

    def tearDown(self):
        self.server.close()

    def test_parse_ports(self):
        self.assertEqual(nettool.parse_ports("80,22,100-102"), [22, 80, 100, 101, 102])
        with self.assertRaises(ValueError):
            nettool.parse_ports("0")

    def test_scan_finds_open_port(self):
        self.assertIn(self.port, nettool.scan_ports("127.0.0.1", [self.port], timeout=1))

    def test_scan_closed_port(self):
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        self.assertEqual(nettool.scan_ports("127.0.0.1", [port], timeout=1), [])

    def test_sweep_localhost(self):
        self.assertEqual(nettool.sweep("127.0.0.1/32", ports=(self.port,), timeout=1), ["127.0.0.1"])

    def test_dns_localhost(self):
        self.assertIn("127.0.0.1", nettool.dns_lookup("localhost")["addresses"])


if __name__ == "__main__":
    unittest.main()
