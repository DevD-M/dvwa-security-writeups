# DVWA Security Assessment — Cross-Site Request Forgery (CSRF)

**Tester:** Devansh
**Target:** DVWA (Damn Vulnerable Web Application)
**Security Level:** Low
**Date:** Day 4 — July 2026

---

## 1. Summary

DVWA's password-change functionality (Low security) is vulnerable to CSRF: the server only validates that a request carries a valid session cookie, without verifying that the request was intentionally initiated by the user. This allowed an attacker-controlled page hosted on a completely different origin to silently change the victim's password using nothing but a hidden `<img>` tag.

Unlike SQLi/XSS, CSRF does not involve injecting malicious input — it abuses the browser's automatic cookie-attachment behavior to forge a legitimate-looking request using the victim's own authenticated session.

---

## 2. Vulnerable Code

**File:** `vulnerabilities/csrf/source/low.php`

```php
if( isset( $_GET[ 'Change' ] ) ) {
    $pass_new  = $_GET[ 'password_new' ];
    $pass_conf = $_GET[ 'password_conf' ];
    if( $pass_new == $pass_conf ) {
        $pass_new = mysqli_real_escape_string($conn, $pass_new);
        $pass_new = md5( $pass_new );
        $insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";
        // ...executes update, no further checks
    }
}
```

**Root cause:**
- Password change is a **state-changing action performed via GET** request (should require POST at minimum).
- **No CSRF token** is generated or validated.
- No `Referer`/`Origin` header validation.
- The only check performed is whether a valid session cookie is present — not whether the request was genuinely initiated by the user via the site's own form.

---

## 3. Attack Demonstration

**Step 1 — Confirm the endpoint accepts GET directly:**
```
http://localhost/vulnerabilities/csrf/?password_new=hacked123&password_conf=hacked123&Change=Change#
```
Result: "Password Changed." — confirms no token requirement.

**Step 2 — Simulate a real forged cross-origin request:**

Malicious page (`evil.html`):
```html
<html>
<body>
<h3>Totally harmless page, nothing to see here</h3>
<img src="http://localhost/vulnerabilities/csrf/?password_new=pwned123&password_conf=pwned123&Change=Change#" width="0" height="0" border="0">
</body>
</html>
```

**Important setup note:** Opening `evil.html` via `file://` did not reliably trigger the attack — browsers restrict cookie attachment from `file://` origins. Serving the page via a local HTTP server (`python3 -m http.server`) so it had a proper `http://` origin (different port than DVWA) accurately simulated a real attacker-hosted page.

**Attack flow:**
1. Victim is logged into DVWA (active session cookie).
2. Victim visits the attacker's page on a different origin.
3. Browser attempts to load the `<img>`, firing a real GET request to DVWA.
4. Browser **automatically attaches the DVWA session cookie** (cookies are domain-scoped, not page/intent-scoped).
5. Server sees a valid session → executes the password change with zero user awareness.

**Verification:** The "Password Changed." message alone is not reliable proof (it can appear as a stale message on page refresh). Verified by logging out and successfully logging in with the new password.

---

## 4. Impact

- Full account takeover possible (password reset without victim consent or awareness).
- Attack requires only a single page visit — no form interaction, no visible indication anything happened.
- In a real application, the same technique could trigger any state-changing action (fund transfers, email changes, etc.) exposed via predictable GET/POST endpoints.

---

## 5. Remediation

1. **CSRF tokens** — a unique, unpredictable, session-tied token must be included in every state-changing request. Server rejects the request if the token is missing or invalid. An attacker's forged request cannot include a valid token since they cannot read it cross-origin.
2. **`SameSite=Strict` (or `Lax`) cookie attribute** — prevents the browser from sending cookies on cross-site requests.
3. **Use POST (not GET) for state-changing actions**, and never treat GET requests as safe to execute side effects.
4. **Re-authentication for sensitive actions** (e.g., require current password to set a new one).

---

## Next Steps
- [x] SQL Injection
- [x] XSS (Reflected, Stored, DOM)
- [x] CSRF
