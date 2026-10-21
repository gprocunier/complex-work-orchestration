import unittest

from checker import errors


class ConfigurationTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(errors({"host": "localhost", "port": 8080}), [])

    def test_host_must_be_nonempty_text(self):
        for host in ["", "  ", None, 42]:
            with self.subTest(host=host):
                self.assertIn("host must be nonempty text", errors({"host": host, "port": 80}))

    def test_port_must_be_integer_not_boolean(self):
        for port in [True, False, "8080", 8.5, None]:
            with self.subTest(port=port):
                self.assertIn("port must be an integer from 1 to 65535", errors({"host": "localhost", "port": port}))

    def test_port_bounds(self):
        for port in [0, -1, 65536]:
            with self.subTest(port=port):
                self.assertTrue(errors({"host": "localhost", "port": port}))
        for port in [1, 65535]:
            with self.subTest(port=port):
                self.assertEqual(errors({"host": "localhost", "port": port}), [])

    def test_missing_fields(self):
        self.assertEqual(len(errors({})), 2)

    def test_root_must_be_object(self):
        for root in [[], None, True, 42, 8.5, "", "text"]:
            with self.subTest(root=root):
                self.assertEqual(errors(root), ["config must be an object"])

    def test_extra_fields_are_ignored(self):
        self.assertEqual(errors({"host": " localhost ", "port": 80, "note": "ignored"}), [])

    def test_invalid_fields_are_reported_independently(self):
        self.assertCountEqual(errors({"host": " ", "port": True}), [
            "host must be nonempty text", "port must be an integer from 1 to 65535"])


if __name__ == "__main__":
    unittest.main()
