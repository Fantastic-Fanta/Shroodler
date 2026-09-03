package extractors

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/shroodler/crawler-go/internal/models"
	"golang.org/x/net/html"
	"gopkg.in/yaml.v3"
)

var (
	cssURL      = regexp.MustCompile(`(?i)url\(\s*['"]?([^'")]+)['"]?\s*\)`)
	metaRefresh = regexp.MustCompile(`(?i)url\s*=\s*['"]?([^'";\s]+)`)
	pagePath    = regexp.MustCompile(`(?i)^(.*)/page/(\d+)/?$`)
	pageQuery   = regexp.MustCompile(`(?i)(?:^|&)page=\d+`)
	fetchStr    = regexp.MustCompile(`fetch\(\s*['"]([^'"]+)['"]`)
	fetchTpl    = regexp.MustCompile("fetch\\(\\s*`([^`$]+)`")
	traceRe     = regexp.MustCompile(`Traceback \(most recent call last\)`)
	hstsAge     = regexp.MustCompile(`(?i)max-age\s*=\s*(\d+)`)
	entropyTok  = regexp.MustCompile(`\b[A-Za-z0-9_\-/+=]{32,64}\b`)
)

type Rule struct {
	ID          string `yaml:"id"`
	Pattern     string `yaml:"pattern"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
}

func RepoRoot() string {
	wd, _ := os.Getwd()
	for d := wd; d != string(filepath.Separator); d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "schema", "finding.schema.json")); err == nil {
			return d
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	return wd
}

func LoadSecretRules() []Rule {
	dir := filepath.Join(RepoRoot(), "packages", "secret-patterns", "rules")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	var rules []Rule
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		var batch []Rule
		if err := yaml.Unmarshal(b, &batch); err == nil {
			rules = append(rules, batch...)
		}
	}
	return rules
}

func wordlistsDir() string {
	return filepath.Join(RepoRoot(), "packages", "secret-patterns", "wordlists")
}

func parseWordlist(path string, asPaths bool) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if asPaths && !strings.HasPrefix(line, "/") {
			line = "/" + line
		}
		out = append(out, line)
	}
	return out
}

var pathWordlists = []string{"common-paths.txt", "source-control.txt", "well-known.txt"}

func LoadCommonPaths() []string {
	seen := map[string]bool{}
	var out []string
	names := append([]string(nil), pathWordlists...)
	sort.Strings(names)
	for _, name := range names {
		for _, line := range parseWordlist(filepath.Join(wordlistsDir(), name), true) {
			if seen[line] {
				continue
			}
			seen[line] = true
			out = append(out, line)
		}
	}
	return out
}

func LoadBackupSuffixes() []string {
	return parseWordlist(filepath.Join(wordlistsDir(), "backup-suffixes.txt"), false)
}

func LoadBackupInteresting() []string {
	names := parseWordlist(filepath.Join(wordlistsDir(), "backup-interesting.txt"), false)
	for i, n := range names {
		names[i] = strings.ToLower(strings.TrimPrefix(n, "/"))
	}
	return names
}

func pathOfURL(raw string) string {
	path := raw
	if i := strings.Index(raw, "://"); i >= 0 {
		rest := raw[i+3:]
		if sl := strings.Index(rest, "/"); sl >= 0 {
			path = rest[sl:]
		} else {
			path = "/"
		}
	}
	if q := strings.Index(path, "?"); q >= 0 {
		path = path[:q]
	}
	if path == "" {
		path = "/"
	}
	if path != "/" && strings.HasSuffix(path, "/") {
		path = strings.TrimSuffix(path, "/")
	}
	return path
}

func IsMutationBase(path string, wordlist, interesting []string) bool {
	path = pathOfURL(path)
	if path == "/" {
		return false
	}
	for _, w := range wordlist {
		if path == w {
			return true
		}
	}
	name := path
	if i := strings.LastIndex(path, "/"); i >= 0 {
		name = path[i+1:]
	}
	name = strings.ToLower(name)
	if name == "" {
		return false
	}
	stem := name
	if i := strings.Index(name, "."); i >= 0 {
		stem = name[:i]
	}
	for _, n := range interesting {
		if name == n || stem == n {
			return true
		}
	}
	return false
}

func MutationPaths(discovered []string) []string {
	suffixes := LoadBackupSuffixes()
	interesting := LoadBackupInteresting()
	wordlist := LoadCommonPaths()
	var bases []string
	seenBase := map[string]bool{}
	for _, raw := range discovered {
		path := pathOfURL(raw)
		if seenBase[path] || !IsMutationBase(path, wordlist, interesting) {
			continue
		}
		seenBase[path] = true
		bases = append(bases, path)
	}
	var out []string
	seenOut := map[string]bool{}
	for _, base := range bases {
		for _, suffix := range suffixes {
			mutated := base + suffix
			if mutated == base || seenOut[mutated] || seenBase[mutated] {
				continue
			}
			seenOut[mutated] = true
			out = append(out, mutated)
		}
	}
	return out
}

func PaginationFamily(rawURL string) string {
	u := rawURL
	path := rawURL
	if i := strings.Index(rawURL, "://"); i >= 0 {
		rest := rawURL[i+3:]
		if sl := strings.Index(rest, "/"); sl >= 0 {
			path = rest[sl:]
		} else {
			path = "/"
		}
		if q := strings.Index(path, "?"); q >= 0 {
			u = path[q+1:]
			path = path[:q]
		} else {
			u = ""
		}
	}
	if m := pagePath.FindStringSubmatch(path); len(m) == 3 {
		return "path:" + m[1] + "/page/N"
	}
	if pageQuery.MatchString(u) {
		return "query:" + path
	}
	return ""
}

func IsHoneypot(n *html.Node) bool {
	for c := n; c != nil; c = c.Parent {
		if c.Type != html.ElementNode {
			continue
		}
		if hasAttr(c, "hidden") {
			return true
		}
		if strings.EqualFold(attr(c, "aria-hidden"), "true") {
			return true
		}
		if strings.Contains(strings.ToLower(attr(c, "class")), "honeypot") {
			return true
		}
		st := compact(attr(c, "style"))
		if strings.Contains(st, "display:none") || strings.Contains(st, "visibility:hidden") || strings.Contains(st, "left:-9999") {
			return true
		}
	}
	return false
}

func ExtractLinks(base, body string) []string {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(raw string) {
		if raw == "" {
			return
		}
		// imported via urls in crawler; keep relative here, crawler normalizes
		if !seen[raw] {
			seen[raw] = true
			out = append(out, raw)
		}
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a":
				if !IsHoneypot(n) {
					add(attr(n, "href"))
				}
			case "form":
				if !IsHoneypot(n) {
					a := attr(n, "action")
					if a == "" {
						a = base
					}
					add(a)
				}
			case "link":
				add(attr(n, "href"))
			case "script":
				add(attr(n, "src"))
			case "meta":
				if strings.EqualFold(attr(n, "http-equiv"), "refresh") {
					if m := metaRefresh.FindStringSubmatch(attr(n, "content")); len(m) == 2 {
						add(m[1])
					}
				}
			case "style":
				if n.FirstChild != nil {
					for _, m := range cssURL.FindAllStringSubmatch(n.FirstChild.Data, -1) {
						add(m[1])
					}
				}
			}
			if st := attr(n, "style"); st != "" {
				for _, m := range cssURL.FindAllStringSubmatch(st, -1) {
					add(m[1])
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

func ExtractForms(body, pageURL string) ([]models.Form, []models.Finding) {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil, nil
	}
	var forms []models.Form
	var findings []models.Finding
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			method := strings.ToUpper(attr(n, "method"))
			if method == "" {
				method = "GET"
			}
			var enc *string
			if e := attr(n, "enctype"); e != "" {
				enc = &e
			}
			var fields []models.FormField
			var fw func(*html.Node)
			fw = func(x *html.Node) {
				if x.Type == html.ElementNode {
					switch x.Data {
					case "input", "select", "textarea":
						name := attr(x, "name")
						if name != "" {
							t := strings.ToLower(attr(x, "type"))
							if x.Data == "select" {
								t = "select"
							} else if x.Data == "textarea" {
								t = "textarea"
							} else if t == "" {
								t = "text"
							}
							f := models.FormField{Name: name, Type: t, Hidden: t == "hidden" || hasAttr(x, "hidden")}
							if hasAttr(x, "disabled") {
								v := true
								f.Disabled = &v
							}
							if hasAttr(x, "readonly") {
								v := true
								f.Readonly = &v
							}
							fields = append(fields, f)
							if t == "password" && strings.EqualFold(attr(x, "autocomplete"), "on") {
								ev := name
								findings = append(findings, models.Finding{
									ID: "autocomplete", Severity: "low", Category: "autocomplete",
									URL: pageURL, Description: "Password field allows autocomplete", Evidence: &ev,
								})
							}
						}
					}
				}
				for c := x.FirstChild; c != nil; c = c.NextSibling {
					fw(c)
				}
			}
			fw(n)
			forms = append(forms, models.Form{Action: attr(n, "action"), Method: method, Fields: fields, Enctype: enc})
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return forms, findings
}

func ExtractHeaders(h map[string]string, pageURL string) (models.HeaderAnalysis, []models.Finding) {
	lower := map[string]string{}
	for k, v := range h {
		lower[strings.ToLower(k)] = v
	}
	tracked := []string{"Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security", "X-Content-Type-Options", "Referrer-Policy"}
	var present, missing []string
	var findings []models.Finding
	for _, name := range tracked {
		if _, ok := lower[strings.ToLower(name)]; ok {
			present = append(present, name)
		} else {
			missing = append(missing, name)
		}
	}
	if _, ok := lower["content-security-policy"]; !ok {
		findings = append(findings, models.Finding{ID: "missing-csp", Severity: "medium", Category: "header", URL: pageURL, Description: "Content-Security-Policy header not set"})
	} else if csp := lower["content-security-policy"]; strings.Contains(strings.ToLower(csp), "unsafe-inline") || strings.Contains(strings.ToLower(csp), "unsafe-eval") {
		ev := csp
		if len(ev) > 120 {
			ev = ev[:120]
		}
		findings = append(findings, models.Finding{ID: "weak-csp", Severity: "low", Category: "header", URL: pageURL, Description: "Content-Security-Policy allows unsafe-inline or unsafe-eval", Evidence: &ev})
	}
	if _, ok := lower["x-frame-options"]; !ok {
		findings = append(findings, models.Finding{ID: "missing-x-frame-options", Severity: "medium", Category: "header", URL: pageURL, Description: "X-Frame-Options header not set"})
	}
	if hsts, ok := lower["strict-transport-security"]; ok {
		if m := hstsAge.FindStringSubmatch(hsts); len(m) == 2 {
			var age int
			for _, ch := range m[1] {
				age = age*10 + int(ch-'0')
			}
			if age < 15552000 {
				ev := hsts
				findings = append(findings, models.Finding{ID: "short-hsts", Severity: "low", Category: "header", URL: pageURL, Description: "HSTS max-age is shorter than 180 days", Evidence: &ev})
			}
		}
	} else if strings.HasPrefix(strings.ToLower(pageURL), "https://") {
		findings = append(findings, models.Finding{ID: "missing-hsts", Severity: "medium", Category: "header", URL: pageURL, Description: "Strict-Transport-Security header not set"})
	}
	if _, ok := lower["x-content-type-options"]; !ok {
		findings = append(findings, models.Finding{ID: "missing-x-content-type-options", Severity: "low", Category: "header", URL: pageURL, Description: "X-Content-Type-Options header not set"})
	}
	if _, ok := lower["referrer-policy"]; !ok {
		findings = append(findings, models.Finding{ID: "missing-referrer-policy", Severity: "info", Category: "header", URL: pageURL, Description: "Referrer-Policy header not set"})
	}
	if srv, ok := lower["server"]; ok {
		if regexp.MustCompile(`\d`).MatchString(srv) {
			ev := srv
			findings = append(findings, models.Finding{ID: "server-version-leak", Severity: "info", Category: "header", URL: pageURL, Description: "Server header discloses a version", Evidence: &ev})
		}
	}
	if xpb, ok := lower["x-powered-by"]; ok {
		ev := xpb
		findings = append(findings, models.Finding{ID: "x-powered-by", Severity: "info", Category: "header", URL: pageURL, Description: "X-Powered-By header discloses the stack", Evidence: &ev})
	}
	return models.HeaderAnalysis{Present: present, Missing: missing}, findings
}

func ExtractVerbose(body, pageURL string, status int) []models.Finding {
	if traceRe.MatchString(body) || (status >= 500 && strings.Contains(body, "File \"")) {
		ev := body
		if len(ev) > 80 {
			ev = ev[:80]
		}
		return []models.Finding{{ID: "verbose-error", Severity: "medium", Category: "verbose-error", URL: pageURL, Description: "Response body contains a verbose stack trace", Evidence: &ev}}
	}
	return nil
}

func Redact(v string) string {
	if len(v) <= 8 {
		return v[:2] + "****"
	}
	return v[:4] + "************" + v[len(v)-4:]
}

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]int{}
	for _, r := range s {
		freq[r]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func ScanSecrets(text, pageURL string, rules []Rule) []models.Finding {
	var findings []models.Finding
	for _, rule := range rules {
		if rule.Pattern == "__ENTROPY__" {
			for _, m := range entropyTok.FindAllString(text, -1) {
				if strings.HasPrefix(m, "eyJ") || strings.HasPrefix(m, "AKIA") {
					continue
				}
				uniq := map[rune]struct{}{}
				for _, r := range m {
					uniq[r] = struct{}{}
				}
				if shannon(m) >= 4.2 && len(uniq) >= 16 {
					ev := Redact(m)
					findings = append(findings, models.Finding{ID: rule.ID, Severity: rule.Severity, Category: "secret", URL: pageURL, Description: rule.Description, Evidence: &ev})
				}
			}
			continue
		}
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			continue
		}
		for _, m := range re.FindAllString(text, -1) {
			ev := Redact(m)
			findings = append(findings, models.Finding{ID: rule.ID, Severity: rule.Severity, Category: "secret", URL: pageURL, Description: rule.Description, Evidence: &ev})
		}
	}
	return findings
}

func ExtractJSEndpoints(source, js string) []models.JSEndpoint {
	var out []models.JSEndpoint
	seen := map[string]bool{}
	add := func(ep string) {
		if ep == "" || seen[ep] {
			return
		}
		seen[ep] = true
		out = append(out, models.JSEndpoint{Source: source, Endpoint: ep})
	}
	for _, m := range fetchStr.FindAllStringSubmatch(js, -1) {
		add(m[1])
	}
	for _, m := range fetchTpl.FindAllStringSubmatch(js, -1) {
		add(m[1])
	}
	return out
}

func ScriptSrcs(body string) []string {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}
	var out []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			if s := attr(n, "src"); s != "" {
				out = append(out, s)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return out
}

func ParseRobots(body string) []string {
	var dis []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "disallow:") {
			p := strings.TrimSpace(line[len("Disallow:"):])
			if i := strings.Index(strings.ToLower(line), "disallow:"); i >= 0 {
				p = strings.TrimSpace(line[i+len("disallow:"):])
			}
			if p != "" {
				dis = append(dis, p)
			}
		}
	}
	return dis
}

func RobotsAllowed(disallows []string, path string) bool {
	for _, d := range disallows {
		if d == "/" {
			return false
		}
		if strings.HasPrefix(path, d) {
			return false
		}
	}
	return true
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

func hasAttr(n *html.Node, key string) bool {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return true
		}
	}
	return false
}

func compact(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), " ", "")
}

// Unused helpers kept for fuzz uniqueness
func Hash(r io.Reader) string {
	h := sha256.New()
	io.Copy(h, r)
	return hex.EncodeToString(h.Sum(nil))
}
