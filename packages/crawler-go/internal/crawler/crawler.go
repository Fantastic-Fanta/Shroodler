package crawler

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/shroodler/crawler-go/internal/extractors"
	"github.com/shroodler/crawler-go/internal/models"
	"github.com/shroodler/crawler-go/internal/urls"
)

const version = "0.1.0"

// defaultUserAgent is sent when Config.UserAgent is empty. It self-identifies
// the scanner (courtesy to the target operator and their logs/WAF), and can
// be overridden with --user-agent for targets that serve different content
// or block requests based on User-Agent.
const defaultUserAgent = "Shroodler/0.1.0 (+https://shroodler.local)"

type Config struct {
	Depth          int // -1 unbounded
	IgnoreRobots   bool
	AllowExternal  bool
	MaxPages       int
	MaxTime        time.Duration // 0 unbounded
	MaxRedirects   int
	Progress       func(pages int, current string)
	Proxy          string
	Cookie         string
	Seeds          []string
	Cookies        []SeedCookie
	Headers        []string
	UserAgent      string
	LoginRecipe    *LoginRecipe
	Mode           string
	NoSitemap      bool
	CheckRateLimit bool
}

type fetchResult struct {
	URL        string
	Status     int
	Headers    map[string]string
	SetCookies []string
	Body       string
	RedirectTo string
	Discovered []string
}

func Crawl(start string, cfg Config) (*models.CrawlResult, error) {
	if cfg.MaxPages == 0 {
		cfg.MaxPages = 400
	}
	if cfg.MaxRedirects == 0 {
		cfg.MaxRedirects = 10
	}
	mode := cfg.Mode
	if mode == "" {
		mode = "static"
	}
	if mode != "static" && mode != "headless" {
		return nil, errString("mode must be static or headless")
	}
	if !cfg.AllowExternal && !urls.IsLocal(start) {
		return nil, errNonLocal
	}
	if !strings.Contains(start, "://") {
		start = "http://" + start
	}
	started := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	t0 := time.Now()
	nreq := 0
	jar, _ := cookiejar.New(nil)
	stopped := "complete"
	client := &http.Client{
		Timeout: 10 * time.Second,
		Jar:     jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	transport := &http.Transport{}
	if cfg.Proxy != "" {
		pu, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(pu)
	}
	ua := cfg.UserAgent
	if ua == "" {
		ua = defaultUserAgent
	}
	client.Transport = &countingTransport{
		base: &headerTransport{base: transport, extra: ParseHeaders(cfg.Headers), userAgent: ua},
		n:    &nreq,
	}
	if cfg.Cookie != "" {
		for _, part := range strings.Split(cfg.Cookie, ";") {
			if c, ok := ParseCookiePair(strings.TrimSpace(part)); ok {
				cfg.Cookies = append(cfg.Cookies, c)
			}
		}
	}
	applySeedCookies(jar, start, cfg.Cookies)
	if cfg.LoginRecipe != nil {
		runLogin(client, *cfg.LoginRecipe, start)
	}

	fetchPage := func(u string) fetchResult {
		return fetchRetry(client, u, "", remainingTimeout(t0, cfg.MaxTime))
	}
	if mode == "headless" {
		hsCookies := append([]SeedCookie{}, cfg.Cookies...)
		if u, err := url.Parse(start); err == nil {
			for _, c := range jar.Cookies(u) {
				hsCookies = append(hsCookies, SeedCookie{Name: c.Name, Value: c.Value, Path: c.Path, Domain: c.Domain})
			}
		}
		hs, err := newHeadless(start, hsCookies, ParseHeaders(cfg.Headers))
		if err != nil {
			return nil, err
		}
		defer hs.close()
		fetchPage = func(u string) fetchResult {
			nreq++
			return hs.fetch(u)
		}
	}

	var robots []string
	var robotsBody string
	if !cfg.IgnoreRobots || !cfg.NoSitemap {
		if body, status, _ := get(client, originJoin(start, "/robots.txt")); status == 200 {
			robotsBody = body
			if !cfg.IgnoreRobots {
				robots = extractors.ParseRobots(body)
			}
		}
	}

	type item struct {
		u     string
		depth int
	}
	queue := []item{{start, 0}}
	for _, extra := range cfg.Seeds {
		if urls.SameOrigin(extra, start) {
			queue = append(queue, item{extra, 0})
		}
	}
	openAPIBase := strings.TrimRight(origin(start), "/")
	for _, p := range extractors.OpenAPIProbePaths {
		queue = append(queue, item{openAPIBase + p, 0})
	}
	seen := map[string]bool{}
	if !cfg.NoSitemap {
		smPages, smDocs := discoverSitemapSeeds(client, start, robotsBody)
		for _, u := range smDocs {
			seen[urls.CanonicalKey(u)] = true
		}
		for _, u := range smPages {
			if urls.SameOrigin(u, start) {
				queue = append(queue, item{u, 0})
			}
		}
	}
	family := map[string]int{}
	var pages []models.Page
	var findings []models.Finding
	var endpoints []models.JSEndpoint
	var corsCandidates []string
	rules := extractors.LoadSecretRules()

	for len(queue) > 0 {
		if hit := budgetHit(cfg, t0, len(pages)); hit != "" {
			stopped = hit
			break
		}
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
		if hit := budgetHit(cfg, t0, len(pages)); hit != "" {
			stopped = hit
			break
		}
		seen[key] = true
		if fam != "" {
			family[fam]++
		}
		res := fetchPage(it.u)
		if res.Status != 200 && extractors.IsOpenAPIProbePath(urls.PathOf(it.u)) {
			continue
		}
		fetchForSourceMap := func(u string) fetchResult {
			return fetchRetry(client, u, "", remainingTimeout(t0, cfg.MaxTime))
		}
		page, f, eps := pageFrom(res, rules, fetchForSourceMap)
		if hasFindingCategory(f, "waf-challenge") && extractors.HasChallengeCookie(res.SetCookies) &&
			budgetHit(cfg, t0, len(pages)) == "" {
			// The challenge response itself set a cookie the vendor's flow
			// normally checks for on the next request (e.g. Cloudflare's
			// cf_clearance) -- the client's cookie jar already has it, so
			// one same-URL retry may already be enough to get past a
			// transient challenge. Still detection-only: this never solves
			// anything, it just avoids treating a one-off hiccup as a
			// durable block.
			retryRes := fetchPage(it.u)
			retryPage, retryF, retryEps := pageFrom(retryRes, rules, fetchForSourceMap)
			if !hasFindingCategory(retryF, "waf-challenge") {
				page, f, eps = retryPage, retryF, retryEps
				res = retryRes
			}
		}
		pages = append(pages, page)
		findings = append(findings, f...)
		endpoints = append(endpoints, eps...)
		if extractors.IsAPIIsh(res.URL, header(res.Headers, "content-type")) {
			corsCandidates = append(corsCandidates, res.URL)
		}
		for _, e := range eps {
			joined := resolve(res.URL, e.Endpoint)
			if extractors.IsAPIPath(e.Endpoint) || extractors.IsAPIPath(joined) {
				corsCandidates = append(corsCandidates, joined)
			}
		}
		if cfg.Progress != nil {
			cfg.Progress(len(pages), res.URL)
		}

		if res.RedirectTo != "" {
			loc := resolve(res.URL, res.RedirectTo)
			if urls.SameOrigin(loc, start) && !seen[urls.CanonicalKey(loc)] {
				queue = append(queue, item{loc, it.depth})
			}
		}
		if res.Status == 200 {
			for _, p := range extractors.ParseOpenAPIPaths(res.Body) {
				u := openAPIBase + p
				if !urls.SameOrigin(u, start) || seen[urls.CanonicalKey(u)] {
					continue
				}
				fam := extractors.PaginationFamily(u)
				if fam != "" && family[fam] >= 8 {
					continue
				}
				queue = append(queue, item{u, it.depth})
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
		for _, d := range res.Discovered {
			if n := urls.Normalize(res.URL, d); n != "" {
				links = append(links, n)
			} else if urls.SameOrigin(d, start) {
				links = append(links, d)
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

	root := strings.TrimRight(origin(start), "/")
	baseline := probeSoft404Baseline(client, root, t0, cfg.MaxTime)
	for _, p := range extractors.LoadCommonPaths() {
		if hit := budgetHit(cfg, t0, len(pages)); hit != "" {
			if stopped == "complete" {
				stopped = hit
			}
			break
		}
		u := root + p
		key := urls.CanonicalKey(u)
		if seen[key] {
			continue
		}
		res := fetchRetry(client, u, "", remainingTimeout(t0, cfg.MaxTime))
		// Checked before the status-code gate below: a 403/503 challenge
		// response would otherwise be silently treated as "not found" and
		// never reported (weak/cookie signatures only fire on 403/503, so
		// they'd never be reached past a status-based continue).
		if challenge := extractors.DetectChallenge(res.Headers, res.Body, res.Status, res.SetCookies); challenge != nil {
			challenge.URL = u
			findings = append(findings, *challenge)
			continue
		}
		if res.Status != 200 || isSoft404(baseline, res) {
			continue
		}
		seen[key] = true
		pages = append(pages, models.Page{URL: u, StatusCode: 200, Forms: []models.Form{}, Params: []string{}, Cookies: []models.Cookie{}, Headers: models.HeaderAnalysis{Present: []string{}, Missing: []string{}}, JSFiles: []string{}})
		ev := p
		findings = append(findings, models.Finding{ID: "exposed-file", Severity: "high", Category: "exposed-file", URL: u, Description: "Common path " + p + " is reachable", Evidence: &ev})
		findings = append(findings, extractors.ScanSecrets(res.Body, u, rules)...)
	}

	var discovered []string
	for _, p := range pages {
		discovered = append(discovered, urls.PathOf(p.URL))
	}
	for _, p := range extractors.MutationPaths(discovered) {
		if hit := budgetHit(cfg, t0, len(pages)); hit != "" {
			if stopped == "complete" {
				stopped = hit
			}
			break
		}
		u := root + p
		key := urls.CanonicalKey(u)
		if seen[key] {
			continue
		}
		res := fetchRetry(client, u, "", remainingTimeout(t0, cfg.MaxTime))
		if challenge := extractors.DetectChallenge(res.Headers, res.Body, res.Status, res.SetCookies); challenge != nil {
			challenge.URL = u
			findings = append(findings, *challenge)
			continue
		}
		if res.Status != 200 || isSoft404(baseline, res) {
			continue
		}
		seen[key] = true
		pages = append(pages, models.Page{URL: u, StatusCode: 200, Forms: []models.Form{}, Params: []string{}, Cookies: []models.Cookie{}, Headers: models.HeaderAnalysis{Present: []string{}, Missing: []string{}}, JSFiles: []string{}})
		ev := p
		findings = append(findings, models.Finding{ID: "exposed-file", Severity: "high", Category: "exposed-file", URL: u, Description: "Backup-name mutation " + p + " is reachable", Evidence: &ev})
	}

	findings = append(findings, probeCORS(client, start, corsCandidates, cfg.AllowExternal)...)

	if budgetHit(cfg, t0, len(pages)) == "" {
		if urls.IsLocal(start) || cfg.AllowExternal {
			gPages, gFindings, gEps := probeGraphQL(client, start, seen)
			pages = append(pages, gPages...)
			findings = append(findings, gFindings...)
			endpoints = append(endpoints, gEps...)
		} else {
			findings = append(findings, graphqlProbeSkippedFinding(start))
		}
	}

	findings = append(findings, extractors.GhostRouteFindings(start, pages, endpoints)...)

	if cfg.CheckRateLimit {
		findings = append(findings, checkRateLimits(client, start, pages)...)
	}

	finished := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	dedupedFindings := dedupeF(findings)
	challengedURLs := map[string]bool{}
	var challengeHits []models.Finding
	for _, f := range dedupedFindings {
		if f.Category == "waf-challenge" {
			challengedURLs[f.URL] = true
			challengeHits = append(challengeHits, f)
		}
	}
	if sitewide := sitewideChallengeFinding(start, len(challengedURLs), len(pages), challengeHits); sitewide != nil {
		dedupedFindings = append(dedupedFindings, *sitewide)
	}
	return &models.CrawlResult{
		Target:         start,
		ScanStartedAt:  started,
		ScanFinishedAt: finished,
		Crawler:        models.CrawlerInfo{Name: "shroodler-go", Version: version, Mode: mode},
		Pages:          pages,
		Findings:       dedupedFindings,
		JSEndpoints:    endpoints,
		Stats: &models.CrawlStats{
			PagesCrawled:    len(pages),
			PagesChallenged: len(challengedURLs),
			Requests:        nreq,
			ElapsedMs:       time.Since(t0).Milliseconds(),
			StoppedReason:   stopped,
		},
	}, nil
}

var errNonLocal = errString("refusing to crawl non-local host; pass --allow-external to scan a remote target")

type errString string

func (e errString) Error() string { return string(e) }

// soft404Baseline fingerprints a site's "not found" response for an
// obviously-nonexistent path. Many apps return HTTP 200 with a branded/
// templated error page for any unknown path instead of a real 404, which
// would otherwise flood the common-path/mutation probes with false-positive
// exposed-file hits (every wordlist entry "exists").
type soft404Baseline struct {
	valid  bool
	status int
	length int
	hash   string
}

func probeSoft404Baseline(client *http.Client, root string, t0 time.Time, maxTime time.Duration) soft404Baseline {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	marker := root + "/__shroodler_nonexistent_" + hex.EncodeToString(buf) + "__"
	res := fetchRetry(client, marker, "", remainingTimeout(t0, maxTime))
	if res.Status == 0 {
		return soft404Baseline{}
	}
	sum := sha256.Sum256([]byte(res.Body))
	return soft404Baseline{valid: true, status: res.Status, length: len(res.Body), hash: hex.EncodeToString(sum[:])}
}

// minLengthForWindow: below this baseline body size, a fixed byte-count
// tolerance window would cover a large fraction of the whole page, silently
// suppressing genuinely different small pages -- require an exact hash
// match instead.
const minLengthForWindow = 200

func isSoft404(baseline soft404Baseline, res fetchResult) bool {
	if !baseline.valid || baseline.status != res.Status {
		return false
	}
	sum := sha256.Sum256([]byte(res.Body))
	if hex.EncodeToString(sum[:]) == baseline.hash {
		return true
	}
	if baseline.length < minLengthForWindow {
		return false
	}
	delta := len(res.Body) - baseline.length
	if delta < 0 {
		delta = -delta
	}
	window := baseline.length / 50 // 2%
	return delta <= window
}

const (
	sitewideChallengeMinPages = 3
	sitewideChallengeMinRatio = 0.3
)

// sitewideChallengeFinding: a single challenged page and a target that's
// WAF-fronted site-wide look identical per-URL -- same category, same
// severity. When a big enough share of the crawl was challenged, add one
// summary finding so a report reader can tell "ignore this one URL" from
// "this whole scan's other findings substantially understate the target's
// real surface".
func sitewideChallengeFinding(start string, pagesChallenged, totalPages int, hits []models.Finding) *models.Finding {
	if totalPages == 0 || pagesChallenged < sitewideChallengeMinPages {
		return nil
	}
	if float64(pagesChallenged)/float64(totalPages) < sitewideChallengeMinRatio {
		return nil
	}
	vendorSet := map[string]bool{}
	for _, f := range hits {
		if f.Evidence != nil && *f.Evidence != "" {
			vendorSet[*f.Evidence] = true
		}
	}
	vendors := make([]string, 0, len(vendorSet))
	for v := range vendorSet {
		vendors = append(vendors, v)
	}
	sort.Strings(vendors)
	vendorText := "a WAF/bot-mitigation vendor"
	if len(vendors) > 0 {
		vendorText = strings.Join(vendors, ", ")
	}
	desc := fmt.Sprintf(
		"%d of %d crawled pages were WAF/bot-mitigation-challenged (%s) -- "+
			"this target appears to be challenged site-wide, not just on one "+
			"page. This scan's other findings substantially understate the "+
			"target's real attack surface. Try --user-agent, or ask the "+
			"target's operator to allowlist the scanner before re-running.",
		pagesChallenged, totalPages, vendorText,
	)
	ev := fmt.Sprintf("%d/%d pages challenged", pagesChallenged, totalPages)
	return &models.Finding{
		ID:          "waf-challenge-sitewide",
		Severity:    "medium",
		Category:    "waf-challenge",
		URL:         start,
		Description: desc,
		Evidence:    &ev,
	}
}

func hasFindingCategory(findings []models.Finding, category string) bool {
	for _, f := range findings {
		if f.Category == category {
			return true
		}
	}
	return false
}

func pageFrom(res fetchResult, rules []extractors.Rule, get func(string) fetchResult) (models.Page, []models.Finding, []models.JSEndpoint) {
	cookies, cf := extractors.ExtractCookies(res.SetCookies, res.URL)
	headers, hf := extractors.ExtractHeaders(res.Headers, res.URL)
	if challenge := extractors.DetectChallenge(res.Headers, res.Body, res.Status, res.SetCookies); challenge != nil {
		challenge.URL = res.URL
		page := models.Page{
			URL:        res.URL,
			StatusCode: res.Status,
			Forms:      []models.Form{},
			Params:     urls.QueryNames(res.URL),
			Cookies:    cookies,
			Headers:    headers,
			JSFiles:    []string{},
		}
		if page.Cookies == nil {
			page.Cookies = []models.Cookie{}
		}
		if page.Params == nil {
			page.Params = []string{}
		}
		all := append([]models.Finding{*challenge}, append(cf, hf...)...)
		return page, all, []models.JSEndpoint{}
	}
	forms, ff := extractors.ExtractForms(res.Body, res.URL)
	vf := extractors.ExtractVerbose(res.Body, res.URL, res.Status)
	sf := extractors.ScanSecrets(res.Body, res.URL, rules)
	jf := extractors.AuditJWTsInText(res.Body, res.URL)
	mf := extractors.ExtractHTMLMarkup(res.Body, res.URL, rules)
	var eps []models.JSEndpoint
	ctype := strings.ToLower(header(res.Headers, "content-type"))
	isJS := strings.Contains(ctype, "javascript") || strings.HasSuffix(res.URL, ".js")
	isHTML := strings.Contains(ctype, "html") || strings.HasPrefix(strings.TrimLeft(res.Body, " \t\r\n"), "<")
	if isJS || isHTML {
		eps = extractors.ExtractJSEndpoints(res.URL, res.Body)
		for _, e := range eps {
			ev := e.Endpoint
			hf = append(hf, models.Finding{ID: "js-endpoint", Severity: "info", Category: "js-endpoint", URL: res.URL, Description: "JS references endpoint " + e.Endpoint, Evidence: &ev})
		}
		if spec := extractors.SourceMappingURL(res.Body); spec != "" {
			if raw := fetchSourceMap(res.URL, spec, get); len(raw) > 0 {
				meps, mf := extractors.ParseSourceMap(res.URL, raw, rules)
				eps = append(eps, meps...)
				hf = append(hf, mf...)
			}
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
	all := append(append(append(append(append(append(ff, cf...), hf...), vf...), sf...), jf...), mf...)
	return page, all, eps
}

func fetchRetry(client *http.Client, raw, cookie string, timeout time.Duration) fetchResult {
	if timeout > 0 {
		prev := client.Timeout
		client.Timeout = timeout
		defer func() { client.Timeout = prev }()
	}
	var last fetchResult
	for i := 0; i < 4; i++ {
		last = doGet(client, raw, cookie)
		if last.Status != 429 {
			return last
		}
		time.Sleep(50 * time.Millisecond)
	}
	return last
}

func probeCORS(client *http.Client, start string, candidates []string, allowExternal bool) []models.Finding {
	if !urls.IsLocal(start) && !allowExternal {
		return []models.Finding{corsProbeSkippedFinding(start)}
	}
	seen := map[string]bool{}
	n := 0
	var out []models.Finding
	for _, raw := range candidates {
		if n >= extractors.MaxCORSProbes {
			break
		}
		if raw == "" || !urls.SameOrigin(raw, start) {
			continue
		}
		if !allowExternal && !urls.IsLocal(raw) {
			continue
		}
		if extractors.IsStaticAsset(raw) {
			continue
		}
		key := urls.CanonicalKey(raw)
		if seen[key] {
			continue
		}
		seen[key] = true
		n++
		out = append(out, extractors.CORSFindings(corsProbeHeaders(client, raw), raw)...)
	}
	return out
}

func corsProbeSkippedFinding(start string) models.Finding {
	return models.Finding{
		ID:       "cors-probe-skipped",
		Severity: "info",
		Category: "scan-note",
		URL:      start,
		Description: "Active CORS probe was skipped because the target is not local " +
			"and --allow-external was not passed. An empty CORS result on a remote " +
			"scan does not mean CORS is safe.",
	}
}

func graphqlProbeSkippedFinding(start string) models.Finding {
	return models.Finding{
		ID:       "graphql-probe-skipped",
		Severity: "info",
		Category: "scan-note",
		URL:      start,
		Description: "Active GraphQL discovery/introspection probe was skipped because " +
			"the target is not local and --allow-external was not passed.",
	}
}

func corsProbeHeaders(client *http.Client, raw string) map[string]string {
	opt := doRequest(client, http.MethodOptions, raw, "", map[string]string{
		"Origin":                        extractors.AttackerOrigin,
		"Access-Control-Request-Method": "GET",
	})
	if header(opt.Headers, "access-control-allow-origin") != "" {
		return opt.Headers
	}
	got := doRequest(client, http.MethodGet, raw, "", map[string]string{
		"Origin": extractors.AttackerOrigin,
	})
	return got.Headers
}

func doGet(client *http.Client, raw, cookie string) fetchResult {
	return doRequest(client, http.MethodGet, raw, cookie, nil)
}

func doRequest(client *http.Client, method, raw, cookie string, extra map[string]string) fetchResult {
	req, err := http.NewRequest(method, raw, nil)
	if err != nil {
		return fetchResult{URL: raw}
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
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
	r := doGet(client, raw, "")
	return r.Body, r.Status, nil
}

func budgetHit(cfg Config, t0 time.Time, nPages int) string {
	if cfg.MaxTime > 0 && time.Since(t0) >= cfg.MaxTime {
		return "max-time"
	}
	if nPages >= cfg.MaxPages {
		return "max-pages"
	}
	return ""
}

func remainingTimeout(t0 time.Time, maxTime time.Duration) time.Duration {
	const fallback = 10 * time.Second
	if maxTime <= 0 {
		return fallback
	}
	left := maxTime - time.Since(t0)
	if left <= 0 {
		return time.Millisecond
	}
	if left < fallback {
		return left
	}
	return fallback
}

func header(h map[string]string, key string) string {
	for k, v := range h {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

type countingTransport struct {
	base http.RoundTripper
	n    *int
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.n != nil {
		*t.n++
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

type headerTransport struct {
	base      http.RoundTripper
	extra     map[string]string
	userAgent string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	if t == nil || (len(t.extra) == 0 && t.userAgent == "") {
		return base.RoundTrip(req)
	}
	clone := req.Clone(req.Context())
	if t.userAgent != "" {
		clone.Header.Set("User-Agent", t.userAgent)
	}
	for k, v := range t.extra {
		clone.Header.Set(k, v)
	}
	return base.RoundTrip(clone)
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

func fetchSourceMap(jsURL, spec string, get func(string) fetchResult) []byte {
	if strings.HasPrefix(spec, "data:") {
		return extractors.DecodeDataURL(spec)
	}
	if get == nil {
		return nil
	}
	u := urls.Normalize(jsURL, spec)
	if u == "" || !urls.SameOrigin(u, jsURL) {
		return nil
	}
	r := get(u)
	if r.Status != 200 {
		return nil
	}
	return []byte(r.Body)
}

func probeGraphQL(client *http.Client, start string, seen map[string]bool) ([]models.Page, []models.Finding, []models.JSEndpoint) {
	var pages []models.Page
	var findings []models.Finding
	var endpoints []models.JSEndpoint
	base := strings.TrimRight(origin(start), "/")
	for _, p := range extractors.GraphQLProbePaths {
		u := base + p
		key := urls.CanonicalKey(u)
		body := probeGraphQLTypename(client, u)
		if !extractors.LooksLikeGraphQL(body) {
			continue
		}
		if !seen[key] {
			seen[key] = true
			pages = append(pages, models.Page{
				URL:        u,
				StatusCode: 200,
				Forms:      []models.Form{},
				Params:     []string{},
				Cookies:    []models.Cookie{},
				Headers:    models.HeaderAnalysis{Present: []string{}, Missing: []string{}},
				JSFiles:    []string{},
			})
		}
		var types []string
		if urls.IsLocal(u) {
			types = extractors.ParseGraphQLSchemaTypes(probeGraphQLIntrospection(client, u))
		}
		ev := p
		findings = append(findings, models.Finding{
			ID:          "js-endpoint",
			Severity:    "info",
			Category:    "js-endpoint",
			URL:         u,
			Description: extractors.GraphQLFindingDescription(p, types),
			Evidence:    &ev,
		})
		endpoints = append(endpoints, models.JSEndpoint{Source: u, Endpoint: p})
	}
	return pages, findings, endpoints
}

func probeGraphQLTypename(client *http.Client, raw string) string {
	posted := doJSONPost(client, raw, graphqlJSON(extractors.GraphQLTypenameQuery))
	if extractors.LooksLikeGraphQL(posted.Body) {
		return posted.Body
	}
	got := doGet(client, withQuery(raw, extractors.GraphQLTypenameQuery), "")
	if extractors.LooksLikeGraphQL(got.Body) {
		return got.Body
	}
	if posted.Body != "" {
		return posted.Body
	}
	return got.Body
}

func probeGraphQLIntrospection(client *http.Client, raw string) string {
	posted := doJSONPost(client, raw, graphqlJSON(extractors.GraphQLIntrospectionQuery))
	if posted.Body != "" {
		return posted.Body
	}
	return doGet(client, withQuery(raw, extractors.GraphQLIntrospectionQuery), "").Body
}

func graphqlJSON(query string) string {
	b, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return `{"query":""}`
	}
	return string(b)
}

func withQuery(raw, query string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	q.Set("query", query)
	u.RawQuery = q.Encode()
	return u.String()
}

func doJSONPost(client *http.Client, raw, body string) fetchResult {
	req, err := http.NewRequest(http.MethodPost, raw, bytes.NewReader([]byte(body)))
	if err != nil {
		return fetchResult{URL: raw}
	}
	req.Header.Set("Content-Type", "application/json")
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
