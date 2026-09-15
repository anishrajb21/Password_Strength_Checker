"""
=============================================================================
 TEST CASES for password_strength_checker.py
=============================================================================

 These tests prove that the rules behave the way the documentation says.
 The sample passwords used here are throwaway examples for testing only -
 they are not anyone's real password and must never be used as one.

 Run with:  python test_password_checker.py
=============================================================================
"""

import unittest

from password_strength_checker import (
    analyse_password,
    contains_uppercase,
    contains_lowercase,
    contains_digit,
    contains_special,
    has_repeated_characters,
    has_obvious_pattern,
    is_common_password,
    score_length,
    validate_password,
)


class TestCharacterChecks(unittest.TestCase):
    """Do the individual yes/no checks work?"""

    def test_uppercase_detected(self):
        self.assertTrue(contains_uppercase("hellO"))
        self.assertFalse(contains_uppercase("hello"))

    def test_lowercase_detected(self):
        self.assertTrue(contains_lowercase("HELLo"))
        self.assertFalse(contains_lowercase("HELLO123"))

    def test_digit_detected(self):
        self.assertTrue(contains_digit("abc7"))
        self.assertFalse(contains_digit("abcdef"))

    def test_special_detected(self):
        self.assertTrue(contains_special("abc#"))
        self.assertFalse(contains_special("abc123"))

    def test_repeats_detected(self):
        self.assertTrue(has_repeated_characters("Baaad!"))
        self.assertFalse(has_repeated_characters("Baad!"))

    def test_patterns_detected(self):
        self.assertTrue(has_obvious_pattern("Xqwerty!9"))   # keyboard walk
        self.assertTrue(has_obvious_pattern("Mn1234!z"))    # 1234 sequence
        self.assertFalse(has_obvious_pattern("Mk9#vTz@2"))

    def test_common_password_detected(self):
        self.assertTrue(is_common_password("letmein"))
        self.assertTrue(is_common_password("LetMeIn"))      # case-insensitive
        self.assertFalse(is_common_password("Mk9#vTz@2qL"))


class TestLengthScoring(unittest.TestCase):
    """Does the length band table give the right points?"""

    def test_length_bands(self):
        self.assertEqual(score_length("a" * 5), 0)
        self.assertEqual(score_length("a" * 9), 1)
        self.assertEqual(score_length("a" * 13), 2)
        self.assertEqual(score_length("a" * 20), 3)


class TestWeakPasswords(unittest.TestCase):
    """TEST CASE GROUP 1 - these must all come back WEAK."""

    def test_too_short(self):
        result = analyse_password("Ab1!")
        self.assertEqual(result["rating"], "WEAK")

    def test_leaked_password(self):
        result = analyse_password("password123")
        self.assertEqual(result["rating"], "WEAK")
        self.assertEqual(result["score"], 0)
        self.assertTrue(result["is_common"])

    def test_letters_only(self):
        result = analyse_password("cricketbat")
        self.assertEqual(result["rating"], "WEAK")

    def test_long_but_all_one_character(self):
        result = analyse_password("aaaaaaaaaaaaaaaa")
        self.assertEqual(result["rating"], "WEAK")


class TestMediumPasswords(unittest.TestCase):
    """TEST CASE GROUP 2 - these must all come back MEDIUM."""

    def test_three_types_short(self):
        # 9 chars, upper + lower + digit, no symbol -> 1 + 3 = 4 points
        result = analyse_password("Cricket21")
        self.assertEqual(result["rating"], "MEDIUM")

    def test_all_four_types_but_only_ten_characters(self):
        # All four types but under 12 characters -> 1 + 4 = 5 points
        result = analyse_password("Mk9#vTz@2q")
        self.assertEqual(result["rating"], "MEDIUM")

    def test_long_but_missing_a_symbol(self):
        # 16 chars, no symbol -> 3 + 3 = 6 points, but not all four types
        result = analyse_password("MangoTreeRiver42")
        self.assertEqual(result["rating"], "MEDIUM")


class TestStrongPasswords(unittest.TestCase):
    """TEST CASE GROUP 3 - these must all come back STRONG."""

    def test_long_with_all_four_types(self):
        # 14 chars, all four types, no patterns -> 2 + 4 = 6 points
        result = analyse_password("Vx7$mQ2#pLz9!k")
        self.assertEqual(result["rating"], "STRONG")
        self.assertGreaterEqual(result["score"], 6)

    def test_long_passphrase_with_symbols(self):
        # 20+ chars, all four types -> 3 + 4 = 7 points (maximum)
        result = analyse_password("Blue$Harbour7Lantern!")
        self.assertEqual(result["rating"], "STRONG")
        self.assertEqual(result["score"], 7)

    def test_strong_password_has_high_entropy(self):
        result = analyse_password("Blue$Harbour7Lantern!")
        self.assertGreater(result["entropy"], 60)


class TestPenalties(unittest.TestCase):
    """Do the -1 penalties actually reduce the rating?"""

    def test_repeats_downgrade_a_password(self):
        clean = analyse_password("Vx7$mQ2#pLz9!k")
        messy = analyse_password("Vx7$mQ2#pLzzz!")
        self.assertGreater(clean["score"], messy["score"])

    def test_sequence_downgrades_a_password(self):
        clean = analyse_password("Vx7$mQ2#pLz9!k")
        messy = analyse_password("Vx7$mQ2#pL1234")
        self.assertGreater(clean["score"], messy["score"])


class TestInputValidation(unittest.TestCase):
    """Edge cases - the program must not crash on odd input."""

    def test_empty_input_rejected(self):
        self.assertIsNotNone(validate_password(""))

    def test_spaces_only_rejected(self):
        self.assertIsNotNone(validate_password("     "))

    def test_overlong_input_rejected(self):
        self.assertIsNotNone(validate_password("a" * 500))

    def test_normal_input_accepted(self):
        self.assertIsNone(validate_password("Vx7$mQ2#pLz9!k"))

    def test_empty_string_does_not_crash_analyser(self):
        result = analyse_password("")
        self.assertEqual(result["rating"], "WEAK")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["entropy"], 0.0)

    def test_unicode_does_not_crash(self):
        result = analyse_password("Pässwörd9!xyzQ")
        self.assertIn(result["rating"], ("WEAK", "MEDIUM", "STRONG"))


class TestPrivacy(unittest.TestCase):
    """The report must never contain the password itself."""

    def test_password_not_stored_in_results(self):
        secret = "Blue$Harbour7Lantern!"
        result = analyse_password(secret)
        for value in result.values():
            self.assertNotEqual(value, secret)
        for reason in result["reasons"]:
            self.assertNotIn(secret, reason)


if __name__ == "__main__":
    unittest.main(verbosity=2)
