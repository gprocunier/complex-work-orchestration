import unittest

from calc.ops import divide


class DivideTests(unittest.TestCase):
    def test_divides(self):
        self.assertEqual(divide(6, 3), 2)
