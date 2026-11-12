import unittest

from calc.ops import divide


class DivideTests(unittest.TestCase):
    def test_divides(self):
        self.assertEqual(divide(6, 3), 2)

    def test_division_by_zero_is_a_value_error(self):
        with self.assertRaises(ValueError):
            divide(1, 0)
