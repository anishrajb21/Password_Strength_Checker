# Password Strength Checker
### Industrial Training / Cybersecurity Internship — Project 1
**Language:** Python 3 (standard library only, no installation needed)

---

## 1. Files in this project

| File | Purpose |
|---|---|
| `password_strength_checker.py` | The complete program |
| `test_password_checker.py` | 27 automated test cases |
| `README.md` | This report |

**How to run:**

```bash
python password_strength_checker.py          # normal interactive mode
python password_strength_checker.py --demo   # analyses built-in sample passwords
python test_password_checker.py              # runs all 27 test cases
```

---

## 2. How the program works

The program is split into six clearly labelled sections so each part does one job.

**Section 1 — Configuration.** All the rules (the symbol list, the leaked-password list, the minimum length) are stored as constants at the top. If a policy changes, you edit one line instead of hunting through the code.

**Section 2 — Character checks.** Six small functions each answer a single yes/no question: does the password contain an uppercase letter, a lowercase letter, a digit, a symbol, a repeated character, or a predictable pattern? Each one loops over the password character by character and returns `True` as soon as it finds what it is looking for. This is the "string manipulation and character checking" part of the project.

**Section 3 — Scoring.** `analyse_password()` calls all the checks, adds up the points, subtracts penalties, converts the score into a rating, and builds two lists: the *reasons* for the rating and the *suggestions* for improving it. Importantly, it **returns** a dictionary of results rather than printing anything. This keeps the logic separate from the display, which is why the same function can be used by the program, by the tests, and later by a website.

**Section 4 — Display.** `print_report()` formats the dictionary into a readable report with a `[#####--]` strength meter. It prints the score, the rating, the reasons and the advice — but never the password.

**Section 5 — Input handling.** `getpass.getpass()` hides the password while it is being typed, exactly like a real login prompt. `validate_password()` then rejects empty input, whitespace-only input, and anything over 128 characters before analysis begins.

**Section 6 — Main loop.** A `while` loop lets the user test several passwords in one session. After each analysis the variable holding the password is set to `None` and deleted, so it does not linger in memory.

---

## 3. The password-strength rules

### Step 1 — Points for length (0–3 points)

Length is the single biggest factor in how long a password takes to crack, so it carries the most weight.

| Length | Points |
|---|---|
| 0–7 characters | 0 |
| 8–11 characters | 1 |
| 12–15 characters | 2 |
| 16 or more characters | 3 |

### Step 2 — Points for character variety (0–4 points)

One point each for: a **lowercase** letter, an **uppercase** letter, a **digit**, and a **special symbol**. Every extra character type multiplies the number of combinations an attacker has to try.

**Maximum possible score: 7 points.**

### Step 3 — Penalties (−1 each)

| Problem | Why it is penalised |
|---|---|
| Same character 3+ times in a row (`aaa`) | Repeats add length without adding unpredictability |
| Keyboard walk or sequence (`qwerty`, `1234`, `abcd`) | Cracking tools try these patterns first |

The score can never fall below 0.

### Step 4 — The leaked-password override

If the password appears in the built-in list of commonly leaked passwords, the score is **forced to 0 and the rating to WEAK**, no matter how long it is. A password already sitting in a public wordlist is found in under a second, so length and symbols cannot rescue it. This is a deliberate hard override, not a penalty.

### Step 5 — Score to rating

| Rating | Conditions |
|---|---|
| **WEAK** | Fewer than 8 characters, **or** in the leaked list, **or** score ≤ 3 |
| **MEDIUM** | Score of 4 or 5, **or** a score of 6+ that is missing one of the four character types |
| **STRONG** | Score ≥ 6 **and** at least 12 characters **and** all four character types present |

Note that a high score alone is not enough for STRONG. The password must *also* clear the length floor and use all four character types — this stops a very long but simple password (`mangomangomangomango`) from sneaking into the top band.

### Bonus measurement — entropy

The program also reports **entropy in bits**, calculated as `length × log₂(pool size)`, where pool size is how many possible characters exist per position (26 lowercase + 26 uppercase + 10 digits + 32 symbols = up to 94). Roughly speaking, under 40 bits is trivially crackable, 60–80 bits is reasonable, and 80+ bits is strong. It is shown as extra information and does not affect the rating.

---

## 4. Example inputs and outputs

### Example A — a leaked password (`sunshine`)

```
==========================================================
 PASSWORD ANALYSIS REPORT
==========================================================
 Password entered : ************  (hidden for security)
 Strength meter   : [-------]  0/7
 Strength rating  : WEAK
----------------------------------------------------------
 WHY THIS RATING:
   - This password appears in public lists of leaked passwords.
   - 8 characters long (1/3 length points).
   - Uses 1/4 character types: lowercase.
   - Estimated entropy: 37.6 bits.

 HOW TO IMPROVE:
   - Choose something completely different - this one is already known.
   - Make it at least 12 characters (16+ is better).
   - Add an uppercase letter.
   - Add a number.
   - Add a special symbol such as ! @ # $ % or &.
==========================================================
```

### Example B — a typical "looks fine" password (`Winter2024!`)

```
==========================================================
 PASSWORD ANALYSIS REPORT
==========================================================
 Password entered : ************  (hidden for security)
 Strength meter   : [#####--]  5/7
 Strength rating  : MEDIUM
----------------------------------------------------------
 WHY THIS RATING:
   - 11 characters long (1/3 length points).
   - Uses 4/4 character types: lowercase, uppercase, digits, symbols.
   - Estimated entropy: 72.1 bits.

 HOW TO IMPROVE:
   - Make it at least 12 characters (16+ is better).
==========================================================
```

This is a good demonstration of the rules working properly: the password has all four character types, but at 11 characters it earns only 1 of 3 length points, so it lands in MEDIUM. Adding two more characters would push it to STRONG.

### Example C — demo mode output

```
--- DEMO MODE: analysing sample passwords ---
  [#------] WEAK    (1/7)  sample of length 3
  [-------] WEAK    (0/7)  sample of length 6
  [-------] WEAK    (0/7)  sample of length 8
  [####---] MEDIUM  (4/7)  sample of length 9
  [#####--] MEDIUM  (5/7)  sample of length 11
  [#######] STRONG  (7/7)  sample of length 17
  [#####--] MEDIUM  (5/7)  sample of length 12
--- end of demo ---
```

The last line is worth noting: that sample has 12 characters and all four character types, which would normally score 6, but it repeats characters (`aaaBBB111!!!`), so the penalty drops it to 5 and it is rated MEDIUM rather than STRONG.

### Invalid input

```
Enter a password to test (typing is hidden):
  ! No password entered. Please type something.
```

---

## 5. Test cases

`test_password_checker.py` contains **27 tests, all passing**. The key ones:

### Weak

| Test password | Score | Why |
|---|---|---|
| `Ab1!` | 1/7 | Only 4 characters — below the 8-character floor |
| `password123` | 0/7 | On the leaked-password list (hard override) |
| `cricketbat` | 2/7 | Lowercase only, 10 characters |
| `aaaaaaaaaaaaaaaa` | 2/7 | 16 chars earns 3 points, but one character type and a repeat penalty |

### Medium

| Test password | Score | Why |
|---|---|---|
| `Cricket21` | 4/7 | 9 characters, three of four types, no symbol |
| `Mk9#vTz@2q` | 5/7 | All four types, but only 10 characters |
| `MangoTreeRiver42` | 6/7 | 16 characters and a score of 6, but no symbol, so it misses STRONG |

### Strong

| Test password | Score | Why |
|---|---|---|
| `Vx7$mQ2#pLz9!k` | 6/7 | 14 characters, all four types, no patterns |
| `Blue$Harbour7Lantern!` | 7/7 | 21 characters, all four types — maximum score, ~137 bits entropy |

### Penalty, edge-case and privacy tests

- `Vx7$mQ2#pLzzz!` scores lower than `Vx7$mQ2#pLz9!k` — the repeat penalty applies.
- `Vx7$mQ2#pL1234` scores lower than `Vx7$mQ2#pLz9!k` — the sequence penalty applies.
- Empty string, spaces only, 500 characters, and non-ASCII input (`Pässwörd9!xyzQ`) are all handled without crashing.
- A privacy test confirms the password never appears anywhere in the results dictionary or the printed reasons.

*(The passwords above exist only as test data and should never be used for real accounts — they are now published in this report.)*

---

## 6. Cybersecurity concepts demonstrated

**Password entropy.** Strength is about unpredictability, not cleverness. The entropy formula shows mathematically why adding length beats adding one clever symbol substitution.

**Length over complexity.** Adding one character multiplies the search space by the pool size; adding one symbol type only widens it once. This is why length is worth 3 points and each character class only 1, and why NIST's modern guidance (SP 800-63B) emphasises length and screening over forced complexity rules.

**Dictionary and credential-stuffing attacks.** Attackers do not try `aaaa`, `aaab`, `aaac`. They start with leaked password lists from previous breaches. Checking against a known-leaked list mirrors what real login systems do, and is why that check overrides everything else.

**Pattern and keyboard-walk resistance.** Cracking tools such as Hashcat apply rules and masks (`qwerty`, `1234`, capitalise-first-letter, append-year). Penalising these reflects how real attacks work rather than how passwords look to a human.

**Never echo or store secrets.** The password is hidden while typing (`getpass`), never printed back, never logged, never written to disk, and cleared from memory after use. This protects against shoulder surfing and terminal scrollback history — and is a rehearsal for the real rule that production systems store only a salted hash, never the password itself.

**Input validation.** Empty, whitespace-only, oversized and non-ASCII input are all checked before processing. Never trusting user input is the foundation of secure coding.

**Fail-safe defaults.** Anything unrecognised or unscored defaults to WEAK, not STRONG. When a security system is unsure, it should err toward caution.

**Actionable feedback.** Telling a user *why* a password failed and *how* to fix it produces better security outcomes than a bare rejection, which usually just makes people add `1!` to the end.

---

## 7. Suggestions for future improvements

1. **Have I Been Pwned API integration.** Check the password against billions of real breached credentials using k-anonymity: send only the first 5 characters of the SHA-1 hash, compare the rest locally, so the password never leaves the machine.
2. **A full offline wordlist.** Load the RockYou list (14 million entries) into a set or Bloom filter instead of the current 40-entry sample.
3. **Smarter pattern detection.** Detect leetspeak substitutions (`P@ssw0rd` → `password`), dates, phone numbers, and names so they can be matched against the dictionary.
4. **Use the `zxcvbn` library** to produce a realistic estimate of how long the password would survive an offline attack, expressed in seconds/days/centuries.
5. **Hash the password** with bcrypt or Argon2 to demonstrate how passwords are actually stored, and show the resulting hash.
6. **A passphrase generator** that suggests a strong replacement using the Diceware method whenever a password is rated WEAK.
7. **A graphical or web interface** — a Tkinter window or a small Flask app with a live colour-coded strength bar that updates as the user types.
8. **Password policy profiles** so an organisation can configure different thresholds (for example, stricter rules for administrator accounts).
9. **Two-factor authentication guidance**, reinforcing that even a strong password should not be the only defence.
