#!/usr/bin/env python3
"""Password Security Toolkit
Analyze password strength, generate secure passwords/passphrases,
and hash/verify passwords safely. Standard library only.
"""
import argparse
import base64
import getpass
import hashlib
import hmac
import math
import os
import secrets
import string
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PBKDF2_ITERATIONS = 600_000  # OWASP-recommended range for PBKDF2-HMAC-SHA256

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
LEET_MAP = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a",
                          "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})

WORDLIST = [
    "apple", "river", "cloud", "tiger", "maple", "ocean", "piano", "stone",
    "ember", "lunar", "pixel", "rocket", "forest", "violet", "falcon", "harbor",
    "jungle", "marble", "nebula", "orchid", "quartz", "saddle", "thunder",
    "velvet", "walnut", "yellow", "zephyr", "anchor", "bridge", "candle",
    "dragon", "engine", "garden", "hammer", "island", "jacket", "kitten",
    "ladder", "magnet", "needle", "orange", "pepper", "rabbit", "silver",
    "temple", "umbrella", "window", "canyon", "meadow", "comet",
]


# ---------- Strength analysis ----------
def load_common_passwords(path=None):
    path = path or os.path.join(HERE, "common_passwords.txt")
    try:
        with open(path, encoding="utf-8") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


def charset_size(pw):
    size = 0
    if any(c.islower() for c in pw): size += 26
    if any(c.isupper() for c in pw): size += 26
    if any(c.isdigit() for c in pw): size += 10
    if any(c in string.punctuation for c in pw): size += len(string.punctuation)
    if any(c == " " for c in pw): size += 1
    return size


def entropy_bits(pw):
    """Naive upper-bound entropy: length * log2(charset size)."""
    size = charset_size(pw)
    return len(pw) * math.log2(size) if size else 0.0


def has_sequence(pw, n=4):
    """Detect runs like 'abcd', '4321' or keyboard walks like 'qwer'."""
    low = pw.lower()
    for i in range(len(low) - n + 1):
        chunk = low[i:i + n]
        codes = [ord(c) for c in chunk]
        diffs = {codes[j + 1] - codes[j] for j in range(n - 1)}
        if diffs in ({1}, {-1}):
            return True
        for row in KEYBOARD_ROWS:
            if chunk in row or chunk in row[::-1]:
                return True
    return False


def has_repeats(pw, n=3):
    return any(len(set(pw[i:i + n])) == 1 for i in range(len(pw) - n + 1))


def analyze(pw, common=None):
    common = common if common is not None else load_common_passwords()
    feedback, penalty = [], 0
    bits = entropy_bits(pw)

    if len(pw) < 8:
        feedback.append("Too short - use at least 12 characters."); penalty += 2
    elif len(pw) < 12:
        feedback.append("Better with 12+ characters."); penalty += 1

    if pw.lower() in common or pw.lower().translate(LEET_MAP) in common:
        feedback.append("This is a very common password (or a trivial variation)."); penalty += 4
    if has_sequence(pw):
        feedback.append("Contains a sequence or keyboard pattern (e.g. 'abcd', 'qwer')."); penalty += 1
    if has_repeats(pw):
        feedback.append("Contains repeated characters (e.g. 'aaa')."); penalty += 1
    if pw.isalpha() or pw.isdigit():
        feedback.append("Mix letters, numbers and symbols."); penalty += 1

    if bits < 28: base = 0
    elif bits < 36: base = 1
    elif bits < 60: base = 2
    elif bits < 80: base = 3
    else: base = 4
    score = max(0, min(4, base - penalty))

    return {
        "length": len(pw),
        "entropy_bits": round(bits, 1),
        "score": score,
        "label": ["Very weak", "Weak", "Fair", "Strong", "Very strong"][score],
        "feedback": feedback or ["Looks good!"],
    }


# ---------- Generation ----------
def generate_password(length=16, symbols=True):
    """Cryptographically secure random password with all required classes."""
    if length < 8:
        raise ValueError("length must be at least 8")
    alphabet = string.ascii_letters + string.digits + (string.punctuation if symbols else "")
    required = [secrets.choice(string.ascii_lowercase),
                secrets.choice(string.ascii_uppercase),
                secrets.choice(string.digits)]
    if symbols:
        required.append(secrets.choice(string.punctuation))
    rest = [secrets.choice(alphabet) for _ in range(length - len(required))]
    chars = required + rest
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_passphrase(words=4, sep="-"):
    if words < 3:
        raise ValueError("use at least 3 words")
    return sep.join(secrets.choice(WORDLIST) for _ in range(words))


# ---------- Hashing ----------
def hash_password(pw, iterations=PBKDF2_ITERATIONS):
    """Return 'pbkdf2_sha256$iterations$salt$hash' (salted, slow by design)."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(pw, stored):
    try:
        algo, iters, salt_b64, hash_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, int(iters))
        return hmac.compare_digest(dk, expected)  # constant-time comparison
    except (ValueError, TypeError):
        return False


# ---------- CLI ----------
def main(argv=None):
    p = argparse.ArgumentParser(description="Password Security Toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("check", help="analyze a password's strength (prompts securely)")

    g = sub.add_parser("generate", help="generate a random password")
    g.add_argument("-l", "--length", type=int, default=16)
    g.add_argument("--no-symbols", action="store_true")

    ph = sub.add_parser("passphrase", help="generate a word passphrase")
    ph.add_argument("-w", "--words", type=int, default=4)

    sub.add_parser("hash", help="hash a password (prompts securely)")

    v = sub.add_parser("verify", help="verify a password against a stored hash")
    v.add_argument("stored_hash")

    a = p.parse_args(argv)

    if a.cmd == "check":
        r = analyze(getpass.getpass("Password to check: "))
        print(f"Strength : {r['label']} ({r['score']}/4)")
        print(f"Length   : {r['length']}")
        print(f"Entropy  : ~{r['entropy_bits']} bits")
        for f in r["feedback"]:
            print(f" - {f}")
    elif a.cmd == "generate":
        print(generate_password(a.length, not a.no_symbols))
    elif a.cmd == "passphrase":
        print(generate_passphrase(a.words))
    elif a.cmd == "hash":
        print(hash_password(getpass.getpass("Password to hash: ")))
    elif a.cmd == "verify":
        ok = verify_password(getpass.getpass("Password: "), a.stored_hash)
        print("MATCH" if ok else "NO MATCH")
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
