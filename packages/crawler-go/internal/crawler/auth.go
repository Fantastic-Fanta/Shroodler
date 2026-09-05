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
	LogoutURL     string            `json:"logout_url"`
	LogoutMethod  string            `json:"logout_method"`
	ProtectedURL  string            `json:"protected_url"`
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
	if r.LogoutMethod == "" {
		r.LogoutMethod = "GET"
	}
	return &r, nil
}

// resolveOne resolves a recipe URL that may be relative (against seed) or
// already absolute, mirroring Python's auth.py::_resolve_one.
func resolveOne(raw, seed string) string {
	if raw == "" {
		return raw
	}
	if !strings.Contains(raw, "://") {
		return originJoin(seed, raw)
	}
	return raw
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
	resp, err := client.Do(req)
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
