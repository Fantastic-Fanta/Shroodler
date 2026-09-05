package crawler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/html"
)

type SeedCookie struct {
	Name   string
	Value  string
	Domain string
	Path   string
}

type LoginRecipe struct {
	URL           string            `json:"url"`
	Method        string            `json:"method"`
	Fields        map[string]string `json:"fields"`
	IncludeHidden *bool             `json:"include_hidden"`
	LogoutURL     string            `json:"-"`
	LogoutMethod  string            `json:"-"`
	ProtectedURL  string            `json:"-"`
}

// rawLoginRecipe decodes logout_url/logout_method/protected_url leniently
// (as json.RawMessage rather than string) so a malformed value in one of
// these newer, optional fields degrades to "field absent" (disabling just
// the session-fixation/logout-invalidation checks that depend on it)
// instead of a hard parse error that aborts the whole crawl -- mirroring
// Python's auth.py::load_login_recipe, which always coerces successfully
// via str(x) if x else None and never raises on these fields.
type rawLoginRecipe struct {
	LogoutURL    json.RawMessage `json:"logout_url"`
	LogoutMethod json.RawMessage `json:"logout_method"`
	ProtectedURL json.RawMessage `json:"protected_url"`
}

func lenientOptionalString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	// Not a JSON string (a number, object, array, bool, or malformed
	// value) -- treat as absent rather than failing the whole parse.
	return ""
}

type cookieJSON struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"httpOnly"`
}

type storageStateJSON struct {
	Cookies []cookieJSON `json:"cookies"`
}

func LoadCookieFile(path string) ([]SeedCookie, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trim := strings.TrimSpace(string(b))
	if strings.HasPrefix(trim, "{") || strings.HasPrefix(trim, "[") {
		return cookiesFromJSON(b)
	}
	return cookiesFromNetscape(string(b)), nil
}

func cookiesFromJSON(b []byte) ([]SeedCookie, error) {
	var arr []cookieJSON
	if json.Unmarshal(b, &arr) != nil {
		var st storageStateJSON
		if err := json.Unmarshal(b, &st); err != nil {
			return nil, err
		}
		arr = st.Cookies
	}
	var out []SeedCookie
	for _, c := range arr {
		if c.Name == "" {
			continue
		}
		path := c.Path
		if path == "" {
			path = "/"
		}
		out = append(out, SeedCookie{Name: c.Name, Value: c.Value, Domain: strings.TrimPrefix(c.Domain, "."), Path: path})
	}
	return out, nil
}

func cookiesFromNetscape(text string) []SeedCookie {
	var out []SeedCookie
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 7 {
			parts = strings.Fields(line)
		}
		if len(parts) < 7 {
			continue
		}
		path := parts[2]
		if path == "" {
			path = "/"
		}
		out = append(out, SeedCookie{
			Name:   parts[5],
			Value:  parts[6],
			Domain: strings.TrimPrefix(parts[0], "."),
			Path:   path,
		})
	}
	return out
}

func ParseCookiePair(raw string) (SeedCookie, bool) {
	name, value, ok := strings.Cut(raw, "=")
	if !ok {
		return SeedCookie{}, false
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return SeedCookie{}, false
	}
	return SeedCookie{Name: name, Value: strings.TrimSpace(value), Path: "/"}, true
}

func ParseHeaderLine(raw string) (name, value string, ok bool) {
	name, value, found := strings.Cut(raw, ":")
	name = strings.TrimSpace(name)
	if !found || name == "" {
		return "", "", false
	}
	return name, strings.TrimSpace(value), true
}

func ParseHeaders(lines []string) map[string]string {
	out := map[string]string{}
	for _, raw := range lines {
		if n, v, ok := ParseHeaderLine(raw); ok {
			out[n] = v
		}
	}
	return out
}

func LoadLoginRecipe(path string) (*LoginRecipe, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r LoginRecipe
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if r.URL == "" {
		return nil, errString("login recipe missing url")
	}
	if r.Fields == nil {
		r.Fields = map[string]string{}
	}
	if r.Method == "" {
		r.Method = "POST"
	}
	var raw rawLoginRecipe
	if json.Unmarshal(b, &raw) == nil {
		r.LogoutURL = lenientOptionalString(raw.LogoutURL)
		r.ProtectedURL = lenientOptionalString(raw.ProtectedURL)
		r.LogoutMethod = lenientOptionalString(raw.LogoutMethod)
	}
	if r.LogoutMethod == "" {
		r.LogoutMethod = "GET"
	}
	return &r, nil
}

// resolveOne resolves a recipe URL that may be relative (against seed) or
// already absolute, mirroring Python's auth.py::_resolve_one (a plain
// urljoin(seed, raw)). Deliberately uses real RFC 3986 relative resolution
// (url.ResolveReference), not originJoin's simpler "treat as origin-rooted
// path" behavior -- a non-rooted relative value like "logout" needs to
// resolve against seed's directory (e.g. "/account/login" -> "/account/
// logout"), which a naive path replacement gets wrong.
func resolveOne(raw, seed string) string {
	if raw == "" {
		return raw
	}
	if strings.Contains(raw, "://") {
		return raw
	}
	base := seed
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return originJoin(seed, raw)
	}
	refURL, err := url.Parse(raw)
	if err != nil {
		return originJoin(seed, raw)
	}
	return baseURL.ResolveReference(refURL).String()
}

// resolveRecipeURL resolves url/logout_url/protected_url against seed,
// mirroring Python's auth.py::resolve_recipe_url.
func resolveRecipeURL(recipe LoginRecipe, seed string) LoginRecipe {
	resolved := recipe
	resolved.URL = resolveOne(recipe.URL, seed)
	resolved.LogoutURL = resolveOne(recipe.LogoutURL, seed)
	resolved.ProtectedURL = resolveOne(recipe.ProtectedURL, seed)
	return resolved
}

func applySeedCookies(jar http.CookieJar, start string, cookies []SeedCookie) {
	if jar == nil || len(cookies) == 0 {
		return
	}
	u, err := url.Parse(start)
	if err != nil {
		return
	}
	var list []*http.Cookie
	for _, c := range cookies {
		path := c.Path
		if path == "" {
			path = "/"
		}
		list = append(list, &http.Cookie{Name: c.Name, Value: c.Value, Path: path, Domain: c.Domain})
	}
	jar.SetCookies(u, list)
}

func runLogin(client *http.Client, recipe LoginRecipe, seed string) {
	target := recipe.URL
	if !strings.Contains(target, "://") {
		target = originJoin(seed, recipe.URL)
	}
	fields := map[string]string{}
	for k, v := range recipe.Fields {
		fields[k] = v
	}
	include := true
	if recipe.IncludeHidden != nil {
		include = *recipe.IncludeHidden
	}
	if include {
		body, _, _ := get(client, target)
		for k, v := range hiddenInputs(body) {
			if _, ok := fields[k]; !ok {
				fields[k] = v
			}
		}
	}
	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}
	method := strings.ToUpper(recipe.Method)
	if method == "" {
		method = http.MethodPost
	}
	var req *http.Request
	if method == http.MethodGet {
		u, err := url.Parse(target)
		if err != nil {
			return
		}
		q := u.Query()
		for k, v := range fields {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
		req, _ = http.NewRequest(http.MethodGet, u.String(), nil)
	} else {
		req, _ = http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if req == nil {
		return
	}
	// The login submission specifically follows redirects (mirroring
	// Python's run_login_httpx, which overrides the client's normal
	// follow_redirects=False just for this request) -- real login flows
	// commonly bounce through an SSO/interstitial hop before landing on
	// the page that actually rotates the session cookie, and stopping at
	// the first 3xx would miss that. Sharing the same Transport/Jar as
	// the main client keeps cookies/proxy/TLS config consistent; only the
	// redirect policy differs for this one request.
	loginClient := *client
	loginClient.CheckRedirect = nil
	resp, err := loginClient.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 2_000_000))
	resp.Body.Close()
}

func hiddenInputs(body string) map[string]string {
	out := map[string]string{}
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return out
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			if strings.EqualFold(attr(n, "type"), "hidden") {
				name := attr(n, "name")
				if name != "" {
					out[name] = attr(n, "value")
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return out
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}
