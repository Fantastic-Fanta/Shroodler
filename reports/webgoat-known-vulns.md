# WebGoat Known Vulnerabilities (ground truth for Shroodler eval)

## Authentication
- Default creds: guest/guest, webgoat/webgoat
- /WebGoat/login — no rate limiting, no lockout
- JWT weak secret on /WebGoat/JWT/* endpoints

## Authorization / IDOR
- /WebGoat/IDOR/profile/{userId} — access other users' profiles by changing ID
- /WebGoat/access-control/users-admin-fix — vertical priv esc (user→admin)
- Missing function-level access control on /WebGoat/access-control/*

## Injection
- SQL injection: /WebGoat/SqlInjection/attack* endpoints
- XSS (stored): /WebGoat/CrossSiteScripting/stored
- XXE: /WebGoat/xxe/simple (XML upload)
- Path traversal: /WebGoat/PathTraversal/random-picture

## Security Headers (expected Shroodler findings)
- No CSP on most routes
- No X-Frame-Options  
- No HSTS (HTTP, not HTTPS)
- No X-Content-Type-Options

## API surface (good authz diff targets)
- GET /WebGoat/access-control/users — lists all users (admin-only)
- GET /WebGoat/IDOR/profile/{id} — per-user profile (scoped)
- PUT /WebGoat/IDOR/profile/{id} — profile update (scoped)
- GET /WebGoat/access-control/user-hash — per-user hash endpoint
