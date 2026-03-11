# secure-by-design-demo

> A demonstration project for the **Lovebeing Business · Secure by Design for Graduates** session (CN5009, Week 7).

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=alexjhotmail_secure-by-design-demo&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=alexjhotmail_secure-by-design-demo)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=alexjhotmail_secure-by-design-demo&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=alexjhotmail_secure-by-design-demo)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=secure-by-design-demo&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=secure-by-design-demo)

This project is intentionally simple — a basic Flask web app with a login form and a notes feature. The purpose is to demonstrate what **Secure by Design** looks like in practice on a real codebase.

---

## What This App Does

- User registration and login (password hashing with argon2)
- Authenticated notes — users can create and view their own notes
- Basic rate limiting on login endpoint

---

## Running Locally

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/secure-by-design-demo.git
cd secure-by-design-demo

# 2. Copy environment variables
cp .env.example .env
# Edit .env and fill in your own values

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python app.py
```

The app will be available at http://localhost:5000

---

## Security Considerations

> This section demonstrates what hiring teams want to see: not just *what* you built, but *why* you made the security decisions you did.

### Authentication

Passwords are hashed using **argon2id** (via the `argon2-cffi` library) rather than bcrypt or a plain SHA-256 hash.

**Why argon2id over bcrypt?** Argon2 won the Password Hashing Competition (2015) and is the current OWASP recommendation. The key advantage is configurable memory cost: by requiring attackers to use large amounts of memory per guess, it makes GPU-based brute-force attacks significantly more expensive than bcrypt's fixed-cost approach. Argon2id provides resistance to both side-channel attacks (argon2i property) and GPU attacks (argon2d property).

Sessions use a cryptographically random secret key loaded from environment variables — never hardcoded. Session tokens are set with `httponly=True` and `samesite='Strict'` to reduce XSS and CSRF exposure.

### Data Handling

This demo app handles:
- **User credentials** — passwords never stored in plaintext; only argon2id hashes are persisted
- **Notes content** — stored in a local SQLite database; sanitised on input to prevent XSS

At production scale, the following would be added:
- Encryption at rest for the database
- TLS enforced via HSTS header
- Full audit logging for authentication events

**GDPR note:** This app does not process personal data beyond a username and password. If extended to collect real user data, a Privacy Impact Assessment would be required before deployment.

### Known Limitations

This is a demo project. Known security improvements for production:
1. Rate limiting uses an in-memory store — does not persist across restarts or scale horizontally. A Redis-backed solution (e.g., Flask-Limiter with Redis) would be needed at scale.
2. No CSRF tokens on forms. Flask-WTF would add this with minimal effort.
3. SQLite is used for simplicity. A production deployment would use PostgreSQL with parameterised queries enforced at the ORM level.
4. No Content Security Policy header is set. This would be added via Flask-Talisman in a production build.

### Threat Model

A STRIDE threat model for this application is available in [`threat-model/`](./threat-model/). It was created using [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/) and covers the login flow and notes data path.

---

## Dependency Scanning

Dependabot is enabled on this repository. Any dependency with a known CVE will generate an automated pull request within 24 hours of the vulnerability being published to the NVD.

To view current dependency alerts: **Security → Dependabot alerts** (GitHub UI)

---

## Reporting a Vulnerability

See [SECURITY.md](./SECURITY.md) for the responsible disclosure policy.
