import unittest

from textutil.slug import slugify


class SlugTests(unittest.TestCase):
    def test_words_are_joined(self):
        self.assertEqual(slugify("Hello World"), "hello-world")
