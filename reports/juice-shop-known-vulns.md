# Juice Shop Known Vulnerabilities (ground truth for Shroodler eval)

## Authentication / Authorization
- Login bypass via SQL injection (email: ' OR 1=1--  password: anything)
- Password reset without token (IDOR on /rest/user/reset-password)
- Admin panel accessible at /#/administration with any logged-in session
- JWT weak secret (alg:HS256 secret="secret")
- Basket IDOR: GET /rest/basket/:id accessible cross-user

## Information Disclosure
- /ftp/ directory listing — downloadable files including coupons
- /api-docs endpoint — Swagger UI with all REST routes exposed
- Error messages leak stack traces with internal paths
- /metrics endpoint (Prometheus) — unauthenticated

## Injection
- SQL injection on login form
- NoSQL injection on product search (/rest/products/search?q=)
- XSS via product review (stored) and search box (reflected)
- Command injection in file upload (zip slip)

## Security Headers (expected findings for Shroodler)
- Missing CSP on most routes
- No X-Frame-Options
- Missing HSTS
- No SRI on bundled scripts

## APIs worth diffing (authenticated vs unauthenticated)
- GET /api/Users/ — admin-only, returns all users
- GET /rest/basket/:id — should be user-scoped, IDOR if cross-user accessible
- GET /api/Feedbacks/ — admin-only
- DELETE /api/Users/:id — admin-only
- PUT /api/Users/:id — privilege escalation if non-admin can change role
