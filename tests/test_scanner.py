import unittest
from src.port_scanner import PortScanner  # Adjust import if needed

class TestPortScanner(unittest.TestCase):
    def test_scan(self):
        scanner = PortScanner('127.0.0.1', [80, 443])
        open_ports = scanner.scan()
        self.assertIsInstance(open_ports, list)

if __name__ == '__main__':
    unittest.main()
