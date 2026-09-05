package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/shroodler/crawler-go/internal/crawler"
	"github.com/shroodler/crawler-go/internal/lab"
	"github.com/shroodler/crawler-go/internal/models"
	"github.com/shroodler/crawler-go/internal/payload"
	"github.com/shroodler/crawler-go/internal/report"
	"github.com/shroodler/crawler-go/internal/sessions"
	"github.com/shroodler/crawler-go/internal/urls"
	"gopkg.in/yaml.v3"
)

type rcFile struct {
	Mode          string   `yaml:"mode"`
	Depth         *int     `yaml:"depth"`
	MaxPages      *int     `yaml:"max_pages"`
	MaxTime       *float64 `yaml:"max_time"`
	IgnoreRobots  bool     `yaml:"ignore_robots"`
	AllowExternal bool     `yaml:"allow_external"`
	Format        string   `yaml:"format"`
	Header        any      `yaml:"header"`
	Cookie        any      `yaml:"cookie"`
	CookieJar     string   `yaml:"cookie_jar"`
	LoginRecipe   string   `yaml:"login_recipe"`
}

func asStringList(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []string:
		return t
	case []any:
		var out []string
		for _, item := range t {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func loadRC() rcFile {
	for _, p := range []string{".shroodlerrc", filepath.Join(os.Getenv("HOME"), ".shroodlerrc")} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var rc rcFile
		if yaml.Unmarshal(b, &rc) == nil {
			return rc
		}
	}
	return rcFile{}
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	switch args[0] {
	case "crawl":
		return cmdCrawl(args[1:])
	case "diff":
		return cmdDiff(args[1:])
	case "report":
		return cmdReport(args[1:])
	case "payload":
		return cmdPayload(args[1:])
	case "baseline", "expected":
		return cmdBaseline(args[1:])
	case "ingest-sessions":
		return cmdIngest(args[1:])
	case "proxy":
		return cmdProxy(args[1:])
	case "version", "-V", "--version":
		fmt.Println("shroodler-go 0.1.0")
		return 0
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Shroodler Go CLI — crawl, report, diff, payload-test, or drive the proxy.")
	fmt.Fprintln(os.Stderr, "shroodler crawl <url> [--mode static|headless] [--depth N] [--max-pages N] [--max-time SECONDS] [--output out.json] [--ignore-robots] [--no-sitemap] [--allow-external] [--check-rate-limit] [--header 'Name: value'] [--cookie n=v] [--cookie-jar FILE] [--storage-state FILE] [--login-recipe FILE] [--proxy URL] [--seed URL] [--seed-from FILE] [--cookies-from FILE]")
	fmt.Fprintln(os.Stderr, "shroodler ingest-sessions <sessions.jsonl> [--target url] [--output out.json] [--allow-external]")
	fmt.Fprintln(os.Stderr, "shroodler report <findings.json> [--format html|csv|json|sarif|junit|md] [--output out] [--suppressions FILE]")
	fmt.Fprintln(os.Stderr, "shroodler diff <findings.json> <expected_findings.json> [--pages-only] [--gate] [--suppressions FILE] [--format text|junit|sarif]")
	fmt.Fprintln(os.Stderr, "shroodler baseline <findings.json> [--output expected_findings.json] [--name NAME] [--suppressions FILE]")
	fmt.Fprintln(os.Stderr, "shroodler expected <findings.json> [--output expected_findings.json] [--name NAME] [--suppressions FILE]")
	fmt.Fprintln(os.Stderr, "  expected is an alias of baseline; expected_not_found is left empty — add negatives by hand")
	fmt.Fprintln(os.Stderr, "shroodler payload <crawl.json> [--output out.json] [--pack PATH] [--allow-external] [--oob-host HOST]")
	fmt.Fprintln(os.Stderr, "shroodler proxy [shroodler-proxy args...]")
	fmt.Fprintln(os.Stderr, "shroodler version")
}

func findProxyBin() (string, error) {
	if env := os.Getenv("SHROODLER_PROXY_BIN"); env != "" {
		if _, err := os.Stat(env); err != nil {
			return "", err
		}
		return env, nil
	}
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(exe), "..", "proxy-go", "shroodler-proxy")
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
	}
	if path, err := exec.LookPath("shroodler-proxy"); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("shroodler-proxy not found. Run `make bins` or set SHROODLER_PROXY_BIN")
}

func cmdProxy(args []string) int {
	bin, err := findProxyBin()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func cmdCrawl(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	target := args[0]
	rc := loadRC()
	cfg := crawler.Config{Depth: 5, IgnoreRobots: rc.IgnoreRobots, AllowExternal: rc.AllowExternal}
	cfg.Progress = func(pages int, u string) {
		fmt.Printf("PROGRESS pages=%d current=%s\n", pages, u)
		_ = os.Stdout.Sync()
	}
	if rc.Depth != nil {
		cfg.Depth = *rc.Depth
	}
	if rc.Mode != "" {
		cfg.Mode = rc.Mode
	}
	if rc.MaxPages != nil {
		cfg.MaxPages = *rc.MaxPages
	}
	if rc.MaxTime != nil && *rc.MaxTime > 0 {
		cfg.MaxTime = time.Duration(*rc.MaxTime * float64(time.Second))
	}
	cfg.Headers = append(cfg.Headers, asStringList(rc.Header)...)
	for _, raw := range asStringList(rc.Cookie) {
		if c, ok := crawler.ParseCookiePair(raw); ok {
			cfg.Cookies = append(cfg.Cookies, c)
		}
	}
	if rc.CookieJar != "" {
		loaded, err := crawler.LoadCookieFile(rc.CookieJar)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		cfg.Cookies = append(cfg.Cookies, loaded...)
	}
	if rc.LoginRecipe != "" {
		recipe, err := crawler.LoadLoginRecipe(rc.LoginRecipe)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		cfg.LoginRecipe = recipe
	}
	var outPath string
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--depth":
			i++
			fmt.Sscanf(args[i], "%d", &cfg.Depth)
		case "--max-pages":
			i++
			fmt.Sscanf(args[i], "%d", &cfg.MaxPages)
		case "--max-time":
			i++
			var sec float64
			fmt.Sscanf(args[i], "%f", &sec)
			if sec > 0 {
				cfg.MaxTime = time.Duration(sec * float64(time.Second))
			}
		case "--output", "-o":
			i++
			outPath = args[i]
		case "--ignore-robots":
			cfg.IgnoreRobots = true
		case "--no-sitemap":
			cfg.NoSitemap = true
		case "--allow-external":
			cfg.AllowExternal = true
		case "--check-rate-limit":
			cfg.CheckRateLimit = true
		case "--header":
			i++
			cfg.Headers = append(cfg.Headers, args[i])
		case "--cookie":
			i++
			if c, ok := crawler.ParseCookiePair(args[i]); ok {
				cfg.Cookies = append(cfg.Cookies, c)
			}
		case "--cookie-jar", "--storage-state":
			i++
			loaded, err := crawler.LoadCookieFile(args[i])
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			cfg.Cookies = append(cfg.Cookies, loaded...)
		case "--login-recipe":
			i++
			recipe, err := crawler.LoadLoginRecipe(args[i])
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			cfg.LoginRecipe = recipe
		case "--proxy":
			i++
			cfg.Proxy = args[i]
		case "--seed":
			i++
			cfg.Seeds = append(cfg.Seeds, args[i])
		case "--seed-from":
			i++
			list, err := sessions.LoadJSONL(args[i])
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			cfg.Seeds = append(cfg.Seeds, sessions.SeedURLs(list, target)...)
		case "--cookies-from":
			i++
			list, err := sessions.LoadJSONL(args[i])
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			hdr := sessions.CookieHeader(list, target)
			for _, part := range strings.Split(hdr, ";") {
				if c, ok := crawler.ParseCookiePair(strings.TrimSpace(part)); ok {
					cfg.Cookies = append(cfg.Cookies, c)
				}
			}
		case "--mode":
			i++
			cfg.Mode = args[i]
			if cfg.Mode != "static" && cfg.Mode != "headless" {
				fmt.Fprintln(os.Stderr, "mode must be static or headless")
				return 2
			}
		}
	}
	res, err := crawler.Crawl(target, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	b, _ := json.MarshalIndent(res, "", "  ")
	if outPath != "" {
		_ = os.WriteFile(outPath, append(b, '\n'), 0o644)
	} else {
		fmt.Println(string(b))
	}
	return 0
}

func cmdIngest(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	path := args[0]
	target := ""
	allow := false
	var outPath string
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--target":
			i++
			target = args[i]
		case "--output", "-o":
			i++
			outPath = args[i]
		case "--allow-external":
			allow = true
		}
	}
	res, err := crawler.Ingest(path, target, allow)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	b, _ := json.MarshalIndent(res, "", "  ")
	if outPath != "" {
		_ = os.WriteFile(outPath, append(b, '\n'), 0o644)
	} else {
		fmt.Println(string(b))
	}
	return 0
}

func cmdDiff(args []string) int {
	pagesOnly := false
	gate := false
	format := "text"
	var suppressions string
	var outPath string
	var files []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--pages-only":
			pagesOnly = true
		case "--gate":
			gate = true
		case "--suppressions":
			i++
			if i < len(args) {
				suppressions = args[i]
			}
		case "--format":
			i++
			if i < len(args) {
				format = args[i]
			}
		case "--output", "-o":
			i++
			if i < len(args) {
				outPath = args[i]
			}
		default:
			files = append(files, a)
		}
	}
	if len(files) != 2 {
		usage()
		return 2
	}
	actual := loadJSON(files[0])
	expected := loadJSON(files[1])
	rules := lab.LoadSuppressions(suppressions)
	outcome := lab.Diff(actual, expected, pagesOnly, gate, rules)
	if format == "junit" || format == "sarif" {
		var text string
		if format == "junit" {
			text = lab.RenderDiffJUnit(outcome.Errors)
		} else {
			text = lab.RenderDiffSARIF(outcome.Errors)
		}
		if outPath != "" {
			_ = os.WriteFile(outPath, []byte(text), 0o644)
		} else {
			os.Stdout.WriteString(text)
		}
		if len(outcome.Errors) > 0 {
			return 1
		}
		return 0
	}
	for _, e := range outcome.Resolved {
		fmt.Println(e)
	}
	if len(outcome.Errors) > 0 {
		for _, e := range outcome.Errors {
			fmt.Fprintln(os.Stderr, e)
		}
		return 1
	}
	fmt.Println("diff ok")
	return 0
}

func cmdPayload(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	path := args[0]
	var outPath string
	var extra []string
	var allowExternal bool
	var oobHost string
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--output", "-o":
			i++
			if i < len(args) {
				outPath = args[i]
			}
		case "--pack":
			i++
			if i < len(args) {
				extra = append(extra, args[i])
			}
		case "--allow-external":
			allowExternal = true
		case "--oob-host":
			i++
			if i < len(args) {
				oobHost = args[i]
			}
		}
	}
	doc := loadJSON(path)
	packs, err := payload.LoadPacks(extra...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	res, err := payload.Run(doc, nil, packs, allowExternal, oobHost)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	b := payload.Encode(res)
	if outPath != "" {
		if err := os.WriteFile(outPath, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	} else {
		os.Stdout.Write(b)
	}
	return 0
}

func cmdReport(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	format := "html"
	var out string
	var suppressions string
	path := args[0]
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--format":
			i++
			format = args[i]
		case "--output", "-o":
			i++
			out = args[i]
		case "--suppressions":
			i++
			suppressions = args[i]
		}
	}
	doc := loadJSON(path)
	rules := lab.LoadSuppressions(suppressions)
	if len(rules) > 0 {
		doc["findings"] = toAny(lab.FilterFindings(asFindingMaps(doc["findings"]), rules))
	}
	var text string
	switch format {
	case "csv":
		text = csvReport(doc)
	case "json":
		b, _ := json.MarshalIndent(doc, "", "  ")
		text = string(b) + "\n"
	case "sarif":
		text = lab.RenderSARIF(doc)
	case "junit":
		text = lab.RenderJUnit(doc)
	case "md", "markdown":
		text = report.RenderMarkdown(doc)
	case "html":
		text = htmlReport(doc)
	default:
		fmt.Fprintf(os.Stderr, "unsupported format %s\n", format)
		return 2
	}
	if out != "" {
		_ = os.WriteFile(out, []byte(text), 0o644)
	} else {
		os.Stdout.WriteString(text)
	}
	return 0
}

func cmdBaseline(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	path := args[0]
	var out string
	var name string
	var suppressions string
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--output", "-o":
			i++
			out = args[i]
		case "--name":
			i++
			name = args[i]
		case "--suppressions":
			i++
			suppressions = args[i]
		}
	}
	doc := loadJSON(path)
	base := lab.BaselineFromDoc(doc, name, lab.LoadSuppressions(suppressions))
	b, _ := json.MarshalIndent(base, "", "  ")
	text := append(b, '\n')
	if out != "" {
		_ = os.WriteFile(out, text, 0o644)
	} else {
		os.Stdout.Write(text)
	}
	return 0
}

func asFindingMaps(v any) []map[string]any {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(arr))
	for _, item := range arr {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func toAny(ms []map[string]any) []any {
	out := make([]any, 0, len(ms))
	for _, m := range ms {
		out = append(out, m)
	}
	return out
}

func loadJSON(path string) map[string]any {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return m
}

func pathOf(u string) string {
	return urls.PathOf(u)
}

func diffDocs(actual, expected map[string]any, pagesOnly bool) []string {
	return lab.Diff(actual, expected, pagesOnly, false, nil).Errors
}

func csvReport(doc map[string]any) string {
	var b strings.Builder
	b.WriteString("severity,id,category,url,description,evidence\n")
	if findings, ok := doc["findings"].([]any); ok {
		for _, f := range findings {
			m := f.(map[string]any)
			b.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s\n",
				m["severity"], m["id"], m["category"], m["url"], m["description"], m["evidence"]))
		}
	}
	return b.String()
}

func htmlReport(doc map[string]any) string {
	target := fmt.Sprint(doc["target"])
	n := 0
	if findings, ok := doc["findings"].([]any); ok {
		n = len(findings)
	}
	return fmt.Sprintf("<!DOCTYPE html><html><body><h1>Shroodler report</h1><p>Target: %s</p><p>%d findings</p></body></html>\n", target, n)
}

func init() {
	_ = filepath.Separator
	_ = models.CrawlResult{}
	_ = pathOf
}
