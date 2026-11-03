import string
import unittest
import password_toolkit as pt


class TestAnalyze(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        self.assertEqual(pt.analyze("password")["score"], 0)

    def test_leet_variation_detected(self):
        self.assertEqual(pt.analyze("p@ssw0rd")["score"], 0)

    def test_sequence_detected(self):
        self.assertTrue(pt.has_sequence("xxabcdxx"))
        self.assertTrue(pt.has_sequence("qwerty"))

    def test_repeats_detected(self):
        self.assertTrue(pt.has_repeats("baaab"))

    def test_strong_password(self):
        self.assertGreaterEqual(pt.analyze("vT9#kLq2!xRm8@Zp")["score"], 3)


class TestGenerate(unittest.TestCase):
    def test_length_and_classes(self):
        for _ in range(50):
            pw = pt.generate_password(16)
            self.assertEqual(len(pw), 16)
            self.assertTrue(any(c.islower() for c in pw))
            self.assertTrue(any(c.isupper() for c in pw))
            self.assertTrue(any(c.isdigit() for c in pw))
            self.assertTrue(any(c in string.punctuation for c in pw))

    def test_too_short_rejected(self):
        with self.assertRaises(ValueError):
            pt.generate_password(4)

    def test_passphrase(self):
        self.assertEqual(len(pt.generate_passphrase(5).split("-")), 5)


class TestHashing(unittest.TestCase):
    def test_roundtrip(self):
        h = pt.hash_password("S3cret!pw", iterations=1000)
        self.assertTrue(pt.verify_password("S3cret!pw", h))
        self.assertFalse(pt.verify_password("wrong", h))

    def test_salt_makes_hashes_unique(self):
        self.assertNotEqual(pt.hash_password("a", 1000), pt.hash_password("a", 1000))

    def test_malformed_hash(self):
        self.assertFalse(pt.verify_password("x", "garbage"))


if __name__ == "__main__":
    unittest.main()
