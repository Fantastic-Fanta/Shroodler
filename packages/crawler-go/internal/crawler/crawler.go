package crawler

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shroodler/crawler-go/internal/extractors"
	"github.com/shroodler/crawler-go/internal/models"
	"github.com/shroodler/crawler-go/internal/urls"
)

const version = "0.1.0"

type Config struct {
	Depth         int // -1 unbounded
	IgnoreRobots  bool
	AllowExternal bool
	MaxPages      int
	MaxRedirects  int
	Progress      func(pages int, current string)
}

type fetchResult struct {
	URL        string
	Status     int
	Headers    map[string]string
	SetCookies []string
	Body       string
	RedirectTo string
}

func Crawl(start string, cfg Config) (*models.CrawlResult, error) {
	if cfg.MaxPages == 0 {
		cfg.MaxPages = 400
	}
	if cfg.MaxRedirects == 0 {
		cfg.MaxRedirects = 10
	}
	if !cfg.AllowExternal && !urls.IsLocal(start) {
		return nil, errNonLocal
	}
	if !strings.Contains(start, "://") {
		start = "http://" + start
	}
	started := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	client.Transport = &http.Transport{}

	var robots []string
	if !cfg.IgnoreRobots {
		if body, status, _ := get(client, originJoin(start, "/robots.txt")); status == 200 {
			robots = extractors.ParseRobots(body)
		}
	}

	type item struct {
		u     string
		depth int
	}
	queue := []item{{start, 0}}
	seen := map[string]bool{}
	family := map[string]int{}
	var pages []models.Page
	var findings []models.Finding
	var endpoints []models.JSEndpoint
	rules := extractors.LoadSecretRules()

	for len(queue) > 0 && len(pages) < cfg.MaxPages {
		it := queue[0]
		queue = queue[1:]
		key := urls.CanonicalKey(it.u)
		if seen[key] || !urls.SameOrigin(it.u, start) {
			continue
		}
		if !cfg.IgnoreRobots && !extractors.RobotsAllowed(robots, urls.PathOf(it.u)) {
			continue
		}
		fam := extractors.PaginationFamily(it.u)
		if fam != "" && family[fam] >= 8 {
			continue
		}
		seen[key] = true
		if fam != "" {
			family[fam]++
		}
		res := fetchRetry(client, it.u)
		page, f, eps := pageFrom(res, rules)
		pages = append(pages, page)
		findings = append(findings, f...)
		endpoints = append(endpoints, eps...)
		if cfg.Progress != nil {
			cfg.Progress(len(pages), res.URL)
		}

		if res.RedirectTo != "" {
			loc := resolve(res.URL, res.RedirectTo)
			if urls.SameOrigin(loc, start) && !seen[urls.CanonicalKey(loc)] {
				queue = append(queue, item{loc, it.depth})
			}
		}
		if cfg.Depth >= 0 && it.depth >= cfg.Depth {
			continue
		}
		ctype := strings.ToLower(header(res.Headers, "content-type"))
		var links []string
		if strings.Contains(ctype, "html") || strings.HasPrefix(strings.TrimSpace(res.Body), "<") {
			raw := extractors.ExtractLinks(res.URL, res.Body)
			for _, r := range raw {
				if n := urls.Normalize(res.URL, r); n != "" {
					links = append(links, n)
				}
			}
		}
		for _, link := range links {
			if !urls.SameOrigin(link, start) || seen[urls.CanonicalKey(link)] {
				continue
			}
			fam := extractors.PaginationFamily(link)
			if fam != "" && family[fam] >= 8 {
				continue
			}
			queue = append(queue, item{link, it.depth + 1})
		}
	}

	for _, p := range extractors.LoadCommonPaths() {
		u := strings.TrimRight(origin(start), "/") + p
		key := urls.CanonicalKey(u)
		if seen[key] {
			continue
		}
		res := fetchRetry(client, u)
		if res.Status != 200 {
			continue
		}
		seen[key] = true
		pages = append(pages, models.Page{URL: u, StatusCode: 200, Forms: []models.Form{}, Params: []string{}, Cookies: []models.Cookie{}, Headers: models.HeaderAnalysis{Present: []string{}, Missing: []string{}}, JSFiles: []string{}})
		ev := p
		findings = append(findings, models.Finding{ID: "exposed-file", Severity: "high", Category: "exposed-file", URL: u, Description: "Common path " + p + " is reachable", Evidence: &ev})
	}

	finished := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	return &models.CrawlResult{
		Target:         start,
		ScanStartedAt:  started,
		ScanFinishedAt: finished,
		Crawler:        models.CrawlerInfo{Name: "shroodler-go", Version: version, Mode: "static"},
		Pages:          pages,
		Findings:       dedupeF(findings),
		JSEndpoints:    endpoints,
	}, nil
}

var errNonLocal = errString("refusing to crawl non-local host; pass --allow-external for listed public fixtures")

type errString string

func (e errString) Error() string { return string(e) }

func pageFrom(res fetchResult, rules []extractors.Rule) (models.Page, []models.Finding, []models.JSEndpoint) {
	forms, ff := extractors.ExtractForms(res.Body, res.URL)
	cookies, cf := extractors.ExtractCookies(res.SetCookies, res.URL)
	headers, hf := extractors.ExtractHeaders(res.Headers, res.URL)
	vf := extractors.ExtractVerbose(res.Body, res.URL, res.Status)
	sf := extractors.ScanSecrets(res.Body, res.URL, rules)
	var eps []models.JSEndpoint
	ctype := strings.ToLower(header(res.Headers, "content-type"))
	if strings.Contains(ctype, "javascript") || strings.HasSuffix(res.URL, ".js") {
		eps = extractors.ExtractJSEndpoints(res.URL, res.Body)
		for _, e := range eps {
			ev := e.Endpoint
			hf = append(hf, models.Finding{ID: "js-endpoint", Severity: "info", Category: "js-endpoint", URL: res.URL, Description: "JS references endpoint " + e.Endpoint, Evidence: &ev})
		}
	}
	if forms == nil {
		forms = []models.Form{}
	}
	page := models.Page{
		URL:        res.URL,
		StatusCode: res.Status,
		Forms:      forms,
		Params:     urls.QueryNames(res.URL),
		Cookies:    cookies,
		Headers:    headers,
		JSFiles:    extractors.ScriptSrcs(res.Body),
	}
	if page.Cookies == nil {
		page.Cookies = []models.Cookie{}
	}
	if page.Params == nil {
		page.Params = []string{}
	}
	if page.JSFiles == nil {
		page.JSFiles = []string{}
	}
	if page.Headers.Present == nil {
		page.Headers.Present = []string{}
	}
	if page.Headers.Missing == nil {
		page.Headers.Missing = []string{}
	}
	all := append(append(append(append(ff, cf...), hf...), vf...), sf...)
	return page, all, eps
}

func fetchRetry(client *http.Client, raw string) fetchResult {
	var last fetchResult
	for i := 0; i < 4; i++ {
		last = doGet(client, raw)
		if last.Status != 429 {
			return last
		}
		time.Sleep(50 * time.Millisecond)
	}
	return last
}

func doGet(client *http.Client, raw string) fetchResult {
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return fetchResult{URL: raw}
	}
	req.Header.Set("User-Agent", "Shroodler/0.1.0 (+https://shroodler.local)")
	resp, err := client.Do(req)
	if err != nil {
		return fetchResult{URL: raw}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2_000_000))
	hdrs := map[string]string{}
	for k, vs := range resp.Header {
		if len(vs) > 0 {
			hdrs[k] = vs[0]
		}
	}
	out := fetchResult{URL: raw, Status: resp.StatusCode, Headers: hdrs, Body: string(b), SetCookies: resp.Header.Values("Set-Cookie")}
	if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		out.RedirectTo = loc
	}
	return out
}

func get(client *http.Client, raw string) (string, int, error) {
	r := doGet(client, raw)
	return r.Body, r.Status, nil
}

func header(h map[string]string, key string) string {
	for k, v := range h {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

func origin(raw string) string {
	return urls.Origin(raw)
}

func originJoin(base, path string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	u.Path = path
	u.RawQuery = ""
	return u.String()
}

func resolve(base, ref string) string {
	n := urls.Normalize(base, ref)
	if n == "" {
		return ref
	}
	return n
}

func dedupeF(in []models.Finding) []models.Finding {
	seen := map[string]bool{}
	var out []models.Finding
	for _, f := range in {
		k := f.ID + "|" + f.URL
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	if out == nil {
		out = []models.Finding{}
	}
	return out
}
