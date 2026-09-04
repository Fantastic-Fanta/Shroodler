package payload

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/shroodler/crawler-go/internal/extractors"
	"github.com/shroodler/crawler-go/internal/urls"
	"gopkg.in/yaml.v3"
)

const (
	MarkerHost    = "shroodler-oob-test.invalid"
	baselineValue = "shroodler-baseline-probe"
)

type Clause struct {
	StatusGte           *int   `yaml:"status_gte"`
	BodyContains        string `yaml:"body_contains"`
	NewOnly             bool   `yaml:"new_only"`
	Reflected           bool   `yaml:"reflected"`
	ErrorStatusChanged  bool   `yaml:"error_status_changed"`
	TimeDeltaGteMs      *int   `yaml:"time_delta_gte_ms"`
	RedirectedToContain string `yaml:"redirected_to_contains"`
}

type Match struct {
	Any []Clause `yaml:"any"`
	All []Clause `yaml:"all"`
}

type Pack struct {
	ID          string `yaml:"id"`
	FindingID   string `yaml:"finding_id"`
	Payload     string `yaml:"payload"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
	Match       Match  `yaml:"match"`
	RawBody     bool   `yaml:"raw_body"`
	ContentType string `yaml:"content_type"`
}

func (p Pack) findingID() string {
	if p.FindingID != "" {
		return p.FindingID
	}
	return p.ID
}

type Finding struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	URL         string `json:"url"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
}

type Result struct {
	Target   string    `json:"target"`
	Findings []Finding `json:"findings"`
}

func PacksDir() string {
	return filepath.Join(extractors.RepoRoot(), "packages", "payload-tester", "packs")
}

func LoadPacks(extra ...string) ([]Pack, error) {
	packs, err := LoadPacksFrom(PacksDir())
	if err != nil {
		return nil, err
	}
	for _, path := range extra {
		more, err := loadPackPath(path)
		if err != nil {
			return nil, err
		}
		packs = append(packs, more...)
	}
	return packs, nil
}

func loadPackPath(path string) ([]Pack, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return LoadPacksFrom(path)
	}
	return loadPackFile(path)
}

func LoadPacksFrom(dir string) ([]Pack, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	var packs []Pack
	for _, name := range names {
		batch, err := loadPackFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		packs = append(packs, batch...)
	}
	return packs, nil
}

func loadPackFile(path string) ([]Pack, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var batch []Pack
	if err := yaml.Unmarshal(b, &batch); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	name := filepath.Base(path)
	var packs []Pack
	for _, p := range batch {
		if p.ID == "" || p.Payload == "" {
			return nil, fmt.Errorf("%s: pack missing id/payload", name)
		}
		if p.Severity == "" {
			p.Severity = "medium"
		}
		if p.Description == "" {
			p.Description = p.findingID()
		}
		packs = append(packs, p)
	}
	return packs, nil
}

type matchCtx struct {
	elapsedMs        float64
	haveElapsed      bool
	redirectedTo     string
	baselineStatus   int
	haveBaseline     bool
	baselineBody     string
	baselineElapsed  float64
	haveBaselineTime bool
}

func clauseMatches(c Clause, status int, body, payload string, ctx matchCtx) bool {
	if c.StatusGte != nil && status >= *c.StatusGte {
		return true
	}
	if c.ErrorStatusChanged && ctx.haveBaseline && status != ctx.baselineStatus && status >= 400 {
		return true
	}
	if c.BodyContains != "" {
		needle := strings.ToLower(c.BodyContains)
		if strings.Contains(strings.ToLower(body), needle) {
			if !(c.NewOnly && strings.Contains(strings.ToLower(ctx.baselineBody), needle)) {
				return true
			}
		}
	}
	if c.Reflected && strings.Contains(body, payload) {
		return true
	}
	if c.TimeDeltaGteMs != nil && ctx.haveElapsed && ctx.haveBaselineTime {
		if ctx.elapsedMs-ctx.baselineElapsed >= float64(*c.TimeDeltaGteMs) {
			return true
		}
	}
	if c.RedirectedToContain != "" && strings.Contains(strings.ToLower(ctx.redirectedTo), strings.ToLower(c.RedirectedToContain)) {
		return true
	}
	return false
}

func PackMatches(p Pack, status int, body, payload string) bool {
	return packMatchesCtx(p, status, body, payload, matchCtx{})
}

func packMatchesCtx(p Pack, status int, body, payload string, ctx matchCtx) bool {
	if len(p.Match.All) > 0 {
		for _, c := range p.Match.All {
			if !clauseMatches(c, status, body, payload, ctx) {
				return false
			}
		}
		return true
	}
	for _, c := range p.Match.Any {
		if clauseMatches(c, status, body, payload, ctx) {
			return true
		}
	}
	return false
}

func genToken() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 10)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			b[i] = alphabet[0]
			continue
		}
		b[i] = alphabet[n.Int64()]
	}
	return "shrdlr" + string(b)
}

func renderPayload(raw, token string) string {
	r := strings.NewReplacer("{{TOKEN}}", token, "{{MARKER_HOST}}", MarkerHost)
	return r.Replace(raw)
}

func allowed(u string, allowExternal bool) bool {
	return allowExternal || urls.IsLocal(u)
}

// Run sends every loaded pack's payload against each discovered form. When
// allowExternal is false (the default), it refuses to touch anything that
// isn't 127.0.0.1/localhost, mirroring the Python payload-tester and the
// --allow-external flag on `shroodler crawl`.
func Run(crawl map[string]any, client *http.Client, packs []Pack, allowExternal bool) (Result, error) {
	target, _ := crawl["target"].(string)
	if !allowed(target, allowExternal) {
		return Result{}, fmt.Errorf(
			"payload tester refuses non-local targets without --allow-external " +
				"(only scan hosts you are authorized to test)",
		)
	}
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	if packs == nil {
		var err error
		packs, err = LoadPacks()
		if err != nil {
			return Result{}, err
		}
	}
	out := Result{Target: target, Findings: []Finding{}}
	seen := map[string]bool{}
	token := genToken()
	pages, _ := crawl["pages"].([]any)
	for _, raw := range pages {
		page, _ := raw.(map[string]any)
		pageURL, _ := page["url"].(string)
		if !allowed(pageURL, allowExternal) {
			continue
		}
		forms, _ := page["forms"].([]any)
		for _, fr := range forms {
			form, _ := fr.(map[string]any)
			action, _ := form["action"].(string)
			if action == "" {
				action = pageURL
			}
			if strings.HasPrefix(action, "/") {
				u, err := url.Parse(pageURL)
				if err == nil {
					action = u.Scheme + "://" + u.Host + action
				}
			}
			if !allowed(action, allowExternal) {
				continue
			}
			method, _ := form["method"].(string)
			if method == "" {
				method = "GET"
			}
			method = strings.ToUpper(method)
			var fields []string
			if fl, ok := form["fields"].([]any); ok {
				for _, f := range fl {
					fm, _ := f.(map[string]any)
					if n, _ := fm["name"].(string); n != "" {
						fields = append(fields, n)
					}
				}
			}
			if len(fields) == 0 {
				fields = []string{"q"}
			}

			baselineVals := url.Values{}
			for _, name := range fields {
				baselineVals.Set(name, baselineValue)
			}
			var ctx matchCtx
			if bresp, err := fire(client, method, action, baselineVals); err == nil {
				ctx.haveBaseline = true
				ctx.baselineStatus = bresp.status
				ctx.baselineBody = bresp.body
				ctx.haveBaselineTime = true
				ctx.baselineElapsed = bresp.elapsedMs
			}

			for _, pack := range packs {
				payloadStr := renderPayload(pack.Payload, token)
				var resp httpResp
				var err error
				if pack.RawBody {
					if method != "POST" {
						continue
					}
					ct := pack.ContentType
					if ct == "" {
						ct = "application/xml"
					}
					resp, err = fireRaw(client, action, payloadStr, ct)
				} else {
					vals := url.Values{}
					for _, name := range fields {
						vals.Set(name, payloadStr)
					}
					resp, err = fire(client, method, action, vals)
				}
				if err != nil {
					continue
				}
				reqCtx := ctx
				reqCtx.elapsedMs = resp.elapsedMs
				reqCtx.haveElapsed = true
				reqCtx.redirectedTo = resp.redirectedTo
				if !packMatchesCtx(pack, resp.status, resp.body, payloadStr, reqCtx) {
					continue
				}
				fid := pack.findingID()
				key := fid + "|" + action
				if seen[key] {
					continue
				}
				seen[key] = true
				ev := payloadStr
				if len(ev) > 80 {
					ev = ev[:80]
				}
				out.Findings = append(out.Findings, Finding{
					ID: fid, Severity: pack.Severity, Category: "payload",
					URL: action, Description: pack.Description, Evidence: ev,
				})
			}
		}
	}
	return out, nil
}

type httpResp struct {
	status       int
	body         string
	elapsedMs    float64
	redirectedTo string
}

func fireRaw(client *http.Client, action, body, contentType string) (httpResp, error) {
	req, err := http.NewRequest(http.MethodPost, action, strings.NewReader(body))
	if err != nil {
		return httpResp{}, err
	}
	req.Header.Set("Content-Type", contentType)
	return doTimed(client, req)
}

func fire(client *http.Client, method, action string, vals url.Values) (httpResp, error) {
	var req *http.Request
	var err error
	if method == "GET" {
		u, perr := url.Parse(action)
		if perr != nil {
			return httpResp{}, perr
		}
		q := u.Query()
		for k, vs := range vals {
			q.Set(k, vs[0])
		}
		u.RawQuery = q.Encode()
		req, err = http.NewRequest(http.MethodGet, u.String(), nil)
	} else {
		req, err = http.NewRequest(http.MethodPost, action, strings.NewReader(vals.Encode()))
		if req != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	if err != nil {
		return httpResp{}, err
	}
	return doTimed(client, req)
}

func doTimed(client *http.Client, req *http.Request) (httpResp, error) {
	var hops []string
	cc := *client
	cc.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		hops = append(hops, r.URL.String())
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}
	start := time.Now()
	resp, err := cc.Do(req)
	elapsed := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		return httpResp{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1_000_000))
	redirectedTo := strings.Join(hops, " ")
	if resp.Request != nil && resp.Request.URL != nil {
		if redirectedTo != "" {
			redirectedTo += " "
		}
		redirectedTo += resp.Request.URL.String()
	}
	return httpResp{status: resp.StatusCode, body: string(b), elapsedMs: elapsed, redirectedTo: redirectedTo}, nil
}

func Encode(r Result) []byte {
	b, _ := json.MarshalIndent(r, "", "  ")
	return append(b, '\n')
}
