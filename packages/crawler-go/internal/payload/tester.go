package payload

import (
	"encoding/json"
	"fmt"
	"io"
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

type Clause struct {
	StatusGte    *int   `yaml:"status_gte"`
	BodyContains string `yaml:"body_contains"`
	Reflected    bool   `yaml:"reflected"`
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

func clauseMatches(c Clause, status int, body, payload string) bool {
	if c.StatusGte != nil && status >= *c.StatusGte {
		return true
	}
	if c.BodyContains != "" && strings.Contains(strings.ToLower(body), strings.ToLower(c.BodyContains)) {
		return true
	}
	if c.Reflected && strings.Contains(body, payload) {
		return true
	}
	return false
}

func PackMatches(p Pack, status int, body, payload string) bool {
	if len(p.Match.All) > 0 {
		for _, c := range p.Match.All {
			if !clauseMatches(c, status, body, payload) {
				return false
			}
		}
		return true
	}
	for _, c := range p.Match.Any {
		if clauseMatches(c, status, body, payload) {
			return true
		}
	}
	return false
}

func Run(crawl map[string]any, client *http.Client, packs []Pack) (Result, error) {
	target, _ := crawl["target"].(string)
	if !urls.IsLocal(target) {
		return Result{}, fmt.Errorf("payload tester refuses non-local targets")
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
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
	pages, _ := crawl["pages"].([]any)
	for _, raw := range pages {
		page, _ := raw.(map[string]any)
		pageURL, _ := page["url"].(string)
		if !urls.IsLocal(pageURL) {
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
			if !urls.IsLocal(action) {
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
			for _, pack := range packs {
				vals := url.Values{}
				for _, name := range fields {
					vals.Set(name, pack.Payload)
				}
				resp, err := fire(client, method, action, vals)
				if err != nil {
					continue
				}
				if !PackMatches(pack, resp.status, resp.body, pack.Payload) {
					continue
				}
				fid := pack.findingID()
				key := fid + "|" + action
				if seen[key] {
					continue
				}
				seen[key] = true
				ev := pack.Payload
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
	status int
	body   string
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
	resp, err := client.Do(req)
	if err != nil {
		return httpResp{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1_000_000))
	return httpResp{status: resp.StatusCode, body: string(b)}, nil
}

func Encode(r Result) []byte {
	b, _ := json.MarshalIndent(r, "", "  ")
	return append(b, '\n')
}
