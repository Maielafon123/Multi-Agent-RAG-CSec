import unittest

from evals.check_leakage import jaccard, normalized_code_hash, token_shingles


class LeakageHelpersTest(unittest.TestCase):
    def test_normalized_hash_ignores_only_formatting_whitespace(self) -> None:
        left = "void f() {\n  system(x);\n}"
        right = "void  f() { system(x); }"
        self.assertEqual(normalized_code_hash(left), normalized_code_hash(right))


    def test_token_shingle_similarity_detects_identical_code(self) -> None:
        code = "void f(char *x) { char cmd[20]; sprintf(cmd, \"ls %s\", x); system(cmd); }"
        shingles = token_shingles(code)
        self.assertEqual(jaccard(shingles, shingles), 1.0)


if __name__ == "__main__":
    unittest.main()
