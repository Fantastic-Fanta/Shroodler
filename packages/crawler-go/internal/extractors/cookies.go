package extractors

import (
	"net"
	"net/url"
	"strings"

	"github.com/shroodler/crawler-go/internal/models"
)

var sessionExact = map[string]bool{
	"session":           true,
	"sessionid":         true,
	"session_id":        true,
	"sessid":            true,
	"sid":               true,
	"phpsessid":         true,
	"jsessionid":        true,
	"aspsessionid":      true,
	"asp.net_sessionid": true,
	"connect.sid":       true,
	"auth":              true,
	"authtoken":         true,
	"auth_token":        true,
}

type parsedCookie struct {
	cookie models.Cookie
	path   *string
	domain *string
}

func ParseSetCookie(header string) *models.Cookie {
	p := parseSetCookie(header)
	if p == nil {
		return nil
	}
	c := p.cookie
	return &c
}

func parseSetCookie(header string) *parsedCookie {
	parts := strings.Split(header, ";")
	if len(parts) == 0 || !strings.Contains(parts[0], "=") {
		return nil
	}
	name := strings.TrimSpace(strings.SplitN(parts[0], "=", 2)[0])
	if name == "" {
		return nil
	}
	out := &parsedCookie{cookie: models.Cookie{Name: name}}
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		low := strings.ToLower(p)
		if low == "secure" {
			out.cookie.Secure = true
			continue
		}
		if low == "httponly" {
			out.cookie.HTTPOnly = true
			continue
		}
		if !strings.Contains(p, "=") {
			continue
		}
		i := strings.Index(p, "=")
		key := strings.ToLower(strings.TrimSpace(p[:i]))
		val := strings.TrimSpace(p[i+1:])
		switch key {
		case "secure":
			out.cookie.Secure = true
		case "httponly":
			out.cookie.HTTPOnly = true
		case "samesite":
			switch strings.ToLower(val) {
			case "strict":
				s := "Strict"
				out.cookie.SameSite = &s
			case "lax":
				s := "Lax"
				out.cookie.SameSite = &s
			case "none":
				s := "None"
				out.cookie.SameSite = &s
			}
		case "path":
			v := val
			out.path = &v
		case "domain":
			v := val
			out.domain = &v
		}
	}
	return out
}

func sessionBaseName(name string) string {
	if strings.HasPrefix(name, "__Host-") {
		return name[len("__Host-"):]
	}
	if strings.HasPrefix(name, "__Secure-") {
		return name[len("__Secure-"):]
	}
	return name
}

func IsSessionCookie(name string) bool {
	base := strings.ToLower(sessionBaseName(name))
	if sessionExact[base] {
		return true
	}
	return strings.Contains(base, "session")
}

func isIPHost(host string) bool {
	host = strings.Trim(host, "[]")
	return net.ParseIP(host) != nil
}

func isLoopbackOrLocal(host string) bool {
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "localhost" || host == "localhost.localdomain" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func domainIsBroad(host, domain string) bool {
	if domain == "" {
		return false
	}
	domain = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(domain), "."))
	host = strings.ToLower(strings.Trim(host, "[]"))
	if domain == "" || host == "" {
		return false
	}
	if isLoopbackOrLocal(host) || isIPHost(host) {
		return domain != host
	}
	if host == domain {
		return false
	}
	return strings.HasSuffix(host, "."+domain)
}

func cookieFinding(id, severity, pageURL, name, desc string) models.Finding {
	ev := name
	return models.Finding{ID: id, Severity: severity, Category: "cookie", URL: pageURL, Description: desc, Evidence: &ev}
}

// attrsReliable=false is for headless mode, where the Set-Cookie
// "header" strings are actually SYNTHESIZED from the browser's cookie
// jar API, which does not expose Path/Domain the way a real Set-Cookie
// header does -- Path/Domain are always absent in that reconstruction,
// regardless of what the real header said. Review caught that treating
// an absent Path/Domain as violation evidence under those conditions
// made EVERY __Host- cookie in a headless crawl false-positive (100% of
// the time, once per page), including ones a real browser demonstrably
// accepted and stored. With attrsReliable=false, the Domain-presence and
// Path-exactness violation checks are skipped -- only the Secure flag
// (which the jar API does report reliably) is still checked.
func ExtractCookies(headers []string, pageURL string, attrsReliable bool) ([]models.Cookie, []models.Finding) {
	var cookies []models.Cookie
	var findings []models.Finding
	u, _ := url.Parse(pageURL)
	host := ""
	https := false
	if u != nil {
		host = u.Hostname()
		https = strings.EqualFold(u.Scheme, "https")
	}
	// Browsers (Chrome's IsCookiePrefixValid, Firefox) also require
	// __Secure-/__Host- to be SET FROM a secure origin, not just carry
	// the Secure attribute -- treating loopback/localhost as trustworthy
	// even over plain HTTP, matching how real browsers special-case it
	// for local development.
	secureOrigin := https || isLoopbackOrLocal(host)
	for _, raw := range headers {
		p := parseSetCookie(raw)
		if p == nil {
			continue
		}
		c := p.cookie
		cookies = append(cookies, c)
		var pathNorm *string
		if p.path != nil {
			n := strings.TrimSpace(*p.path)
			if n == "" {
				n = "/"
			}
			pathNorm = &n
		}
		// __Secure-/__Host- are contracts a browser enforces at parse
		// time, not hardening advice: a Set-Cookie whose name carries
		// the prefix but doesn't meet the prefix's requirements is
		// REJECTED outright (RFC 6265bis s4.1.3) -- the app thinks it
		// set a cookie and it silently never existed. Deterministic
		// from the header alone (when attrsReliable), independent of
		// whether this looks like a "session" cookie, and distinct
		// from cookie-missing-*-prefix below (a suggestion to adopt a
		// prefix that isn't there yet). Checked FIRST and, if violated,
		// this is the ONLY finding emitted for the cookie: every other
		// attribute-level check below would otherwise describe a
		// cookie that, per this very finding, the browser never
		// actually stored -- reporting both was reviewed as
		// self-contradictory.
		prefixViolated := false
		if strings.HasPrefix(c.Name, "__Secure-") && (!c.Secure || !secureOrigin) {
			var reasons []string
			if !c.Secure {
				reasons = append(reasons, "is missing Secure")
			}
			if !secureOrigin {
				reasons = append(reasons, "was set from a non-secure origin")
			}
			findings = append(findings, cookieFinding(
				"cookie-secure-prefix-violation", "medium", pageURL, c.Name,
				"Cookie "+c.Name+" uses the __Secure- prefix but "+strings.Join(reasons, " and ")+
					" -- browsers reject this Set-Cookie entirely, so the application "+
					"likely thinks it set a cookie that was never actually stored",
			))
			prefixViolated = true
		}
		if strings.HasPrefix(c.Name, "__Host-") {
			var violations []string
			if !c.Secure {
				violations = append(violations, "is missing Secure")
			}
			if !secureOrigin {
				violations = append(violations, "was set from a non-secure origin")
			}
			if attrsReliable && p.domain != nil && strings.TrimSpace(*p.domain) != "" {
				violations = append(violations, "has Domain="+strings.TrimSpace(*p.domain))
			}
			// The __Host- prefix requires an EXPLICIT Path=/ attribute
			// (RFC 6265bis), so an omitted Path (pathNorm == nil) is
			// itself a violation, not just Path != "/".
			if attrsReliable && (pathNorm == nil || *pathNorm != "/") {
				pv := "(none)"
				if pathNorm != nil {
					pv = *pathNorm
				}
				violations = append(violations, "has Path="+pv+" (must be /)")
			}
			if len(violations) > 0 {
				findings = append(findings, cookieFinding(
					"cookie-host-prefix-violation", "medium", pageURL, c.Name,
					"Cookie "+c.Name+" uses the __Host- prefix but "+strings.Join(violations, " and ")+
						" -- browsers reject this Set-Cookie entirely, so the application "+
						"likely thinks it set a cookie that was never actually stored",
				))
				prefixViolated = true
			}
		}
		if prefixViolated {
			continue
		}

		if !c.Secure {
			findings = append(findings, cookieFinding("insecure-cookie", "medium", pageURL, c.Name, "Cookie "+c.Name+" is missing the Secure flag"))
		}
		if !c.HTTPOnly {
			findings = append(findings, cookieFinding("cookie-not-httponly", "low", pageURL, c.Name, "Cookie "+c.Name+" is missing HttpOnly"))
		}
		if c.SameSite != nil && *c.SameSite == "None" && !c.Secure {
			findings = append(findings, cookieFinding("cookie-samesite-none-without-secure", "medium", pageURL, c.Name, "Cookie "+c.Name+" uses SameSite=None without Secure"))
		}
		session := IsSessionCookie(c.Name)
		// A __Host- cookie's Path=/ is mandatory (checked/enforced
		// above), not a broad-scope hardening problem -- flagging it
		// here too would tell the client to both set Path=/ (the
		// prefix requirement) and narrow it away from Path=/ (this
		// suggestion) for the same cookie.
		if session && pathNorm != nil && *pathNorm == "/" && !strings.HasPrefix(c.Name, "__Host-") {
			findings = append(findings, cookieFinding("cookie-path-broad", "info", pageURL, c.Name, "Session cookie "+c.Name+" is scoped to Path=/"))
		}
		domainVal := ""
		if p.domain != nil {
			domainVal = *p.domain
		}
		if domainIsBroad(host, domainVal) {
			findings = append(findings, cookieFinding("cookie-domain-broad", "low", pageURL, c.Name, "Cookie "+c.Name+" Domain="+domainVal+" is broader than host "+host))
		}
		if session && https && c.Secure {
			hasHostPrefix := strings.HasPrefix(c.Name, "__Host-")
			hasSecurePrefix := hasHostPrefix || strings.HasPrefix(c.Name, "__Secure-")
			noDomain := p.domain == nil || strings.TrimSpace(*p.domain) == ""
			if !hasHostPrefix && noDomain && pathNorm != nil && *pathNorm == "/" {
				findings = append(findings, cookieFinding("cookie-missing-host-prefix", "info", pageURL, c.Name, "Session cookie "+c.Name+" on HTTPS could use the __Host- prefix"))
			} else if !hasSecurePrefix {
				findings = append(findings, cookieFinding("cookie-missing-secure-prefix", "low", pageURL, c.Name, "Session cookie "+c.Name+" on HTTPS could use the __Secure- prefix"))
			}
		}
	}
	return cookies, findings
}
