# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import unittest

from conformance import jsonc


class JsoncTest(unittest.TestCase):
    def test_comments_and_commas(self):
        text = '''// head
        { "a": [1, 2, /* inner */ 3,], // tail
          "b": "http://x/y // not a comment", "c": "a\\"/*b*/", }'''
        self.assertEqual(
            jsonc.loads(text),
            {"a": [1, 2, 3], "b": "http://x/y // not a comment", "c": 'a"/*b*/'},
        )

    def test_a_comma_inside_a_string_survives(self):
        self.assertEqual(jsonc.loads('{"a": "foo,] bar,}"}'), {"a": "foo,] bar,}"})
        self.assertEqual(jsonc.loads('{"a": "x\\",] y"}'), {"a": 'x",] y'})
        self.assertEqual(jsonc.loads('[[1,],]'), [[1]])

    def test_line_numbers_survive(self):
        text = '{\n"a": 1,\n/* two\nlines */\n"b": }'
        with self.assertRaises(jsonc.JsoncError) as cm:
            jsonc.loads(text)
        self.assertIn("line 5", str(cm.exception))

    def test_a_block_comment_separates_its_neighbours(self):
        # Newlines alone would turn "1/*c*/2" into valid JSON containing 12.
        for text in ("[1/*c*/2]", '{"a":1/*c*/2}'):
            with self.assertRaises(jsonc.JsoncError):
                jsonc.loads(text)
        self.assertEqual(jsonc.loads('["a"/*c*/,"b"]'), ["a", "b"])

    def test_json5_constants_are_refused(self):
        # json.loads accepts values that other JSON tools reject.
        for text in ('{"a": NaN}', '{"a": Infinity}', '{"a": -Infinity}'):
            with self.assertRaises(jsonc.JsoncError):
                jsonc.loads(text)

    def test_unterminated(self):
        with self.assertRaises(jsonc.JsoncError):
            jsonc.loads("{ /* open")


if __name__ == "__main__":
    unittest.main()
