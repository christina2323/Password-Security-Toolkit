[![Password Security Toolkit Tests](https://github.com/christina2323/Password-Security-Toolkit/actions/workflows/tests.yml/badge.svg)](https://github.com/christina2323/Password-Security-Toolkit/actions/workflows/tests.yml)

# Password Security Toolkit

A command-line cybersecurity project in Python (standard library only) that helps users
create, evaluate, and store passwords securely.

## 1. Problem Statement
Weak, reused, and poorly stored passwords are among the most common causes of account
compromise. Users need a simple way to check how strong a password is, generate strong
ones, and developers need to see how passwords should be stored.

## 2. Objectives
- Estimate password strength using length, character variety, entropy, and known weak patterns.
- Generate cryptographically secure passwords and passphrases.
- Demonstrate secure storage using salted, slow hashing.

## 3. Features
| Module | What it does | Security concept |
|---|---|---|
| `check` | Scores a password 0-4 and gives feedback | Entropy, dictionary attacks, pattern detection |
| `generate` | Random password with all character classes | CSPRNG (`secrets`), not `random` |
| `passphrase` | Random multi-word passphrase | Length over complexity |
| `hash` / `verify` | PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random salt | Salting, key stretching, constant-time comparison |

## 4. How to Run
Requires Python 3.8+.

```bash
python password_toolkit.py check          # prompts for a password (hidden input)
python password_toolkit.py generate -l 20
python password_toolkit.py generate --no-symbols
python password_toolkit.py passphrase -w 5
python password_toolkit.py hash           # prints a storable hash string
python password_toolkit.py verify "<hash string>"
python -m unittest -v                     # run the test suite
```

## 5. Design and Methodology
**Strength analysis.** Entropy is estimated as `length x log2(charset size)`. This is an upper
bound, so penalties are applied for: very short length, entries in a common-password list
(including "leetspeak" variants like `p@ssw0rd`), sequences/keyboard walks (`abcd`, `qwer`),
repeated characters (`aaa`), and letters-only or digits-only passwords. The final score is
the entropy tier minus penalties.

**Generation.** Uses Python's `secrets` module (OS-level CSPRNG). One character from each
required class is guaranteed, the rest are random, then the result is shuffled with
`SystemRandom`.

**Hashing.** Passwords are never stored in plain text. Each is hashed with PBKDF2-HMAC-SHA256
using a unique random salt (defeats rainbow tables) and 600,000 iterations (slows brute
force). Verification uses `hmac.compare_digest` to avoid timing attacks.
Stored format: `pbkdf2_sha256$iterations$salt$hash`.

**Safe input.** `getpass` is used so passwords are never echoed to the screen or saved in
shell history as command arguments.

## 6. Testing
11 unit tests cover common/leet passwords, sequences, repeats, strong passwords, generator
length and class guarantees, hash round-trip, salt uniqueness, and malformed hash handling.

## 7. Limitations
- The common-password list is small (40 entries); real systems use lists with millions of
  entries or services like Have I Been Pwned.
- Entropy is an estimate, not a guarantee.
- The passphrase wordlist is short (50 words); real passphrase generators use 7,776+ words (Diceware).
- PBKDF2 is acceptable, but Argon2id or bcrypt is preferred when third-party libraries are allowed.

## 8. Future Improvements
- Add a larger wordlist (e.g. `rockyou`-style list for defensive checking).
- Check passwords against the Have I Been Pwned k-anonymity API.
- Add a GUI (Tkinter) or a web interface (Flask).
- Switch hashing to Argon2id.

## 9. Conclusion
The toolkit shows three core defensive practices: choosing strong credentials, generating
them securely, and storing them safely.

## Project Structure
```
password-toolkit/
  password_toolkit.py        # main program (CLI + logic)
  common_passwords.txt       # weak-password list
  test_password_toolkit.py   # unit tests
  README.md                  # this report
```
