package urls

import (
	"net"
	"net/url"
	"sort"
	"strings"
)

func Origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Scheme + "://" + u.Host
}

func IsLocal(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0.0.0.0" {
		return true
	}
	return strings.HasSuffix(host, ".local")
}

func SameOrigin(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil {
		return false
	}
	pa, _ := port(ua)
	pb, _ := port(ub)
	return ua.Scheme == ub.Scheme && strings.EqualFold(ua.Hostname(), ub.Hostname()) && pa == pb
}

func port(u *url.URL) (string, error) {
	if u.Port() != "" {
		return u.Port(), nil
	}
	if u.Scheme == "https" {
		return "443", nil
	}
	return "80", nil
}

func Normalize(base, href string) string {
	href = strings.TrimSpace(href)
	if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(strings.ToLower(href), "javascript:") ||
		strings.HasPrefix(strings.ToLower(href), "mailto:") || strings.HasPrefix(strings.ToLower(href), "data:") {
		return ""
	}
	bu, err := url.Parse(base)
	if err != nil {
		return ""
	}
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	out := bu.ResolveReference(ref)
	if out.Scheme != "http" && out.Scheme != "https" {
		return ""
	}
	out.Fragment = ""
	if out.Path == "" {
		out.Path = "/"
	}
	return out.String()
}

func CanonicalKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	if path != "/" && strings.HasSuffix(path, "/") {
		path = strings.TrimSuffix(path, "/")
	}
	q := u.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		vals := q[k]
		sort.Strings(vals)
		for _, v := range vals {
			if b.Len() > 0 {
				b.WriteByte('&')
			}
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(v)
			_ = i
		}
	}
	host := strings.ToLower(u.Hostname())
	p := u.Port()
	if p != "" && !((u.Scheme == "http" && p == "80") || (u.Scheme == "https" && p == "443")) {
		host = net.JoinHostPort(host, p)
	}
	out := u.Scheme + "://" + host + path
	if b.Len() > 0 {
		out += "?" + b.String()
	}
	return out
}

func PathOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return "/"
	}
	return u.Path
}

func QueryNames(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var names []string
	for k := range u.Query() {
		if !seen[k] {
			seen[k] = true
			names = append(names, k)
		}
	}
	sort.Strings(names)
	return names
}
