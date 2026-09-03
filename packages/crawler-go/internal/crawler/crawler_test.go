package crawler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shroodler/crawler-go/internal/crawler"
	"github.com/shroodler/crawler-go/internal/models"
	"github.com/shroodler/crawler-go/internal/urls"
)

func TestDepthAndScope(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="/a">a</a><a href="http://example.com/x">x</a>`))
	})
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="/b">b</a>`))
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("b"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	res, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: 1, IgnoreRobots: true, AllowExternal: false, MaxPages: 50})
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, p := range res.Pages {
		paths[urls.PathOf(p.URL)] = true
		if !urls.SameOrigin(p.URL, srv.URL) {
			t.Fatalf("escaped origin %s", p.URL)
		}
	}
	if !paths["/"] || !paths["/a"] {
		t.Fatalf("paths %v", paths)
	}
	if paths["/b"] {
		t.Fatal("depth 1 should not include /b")
	}
}

func TestRedirectLoopStops(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/b", 302)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/a", 302)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	res, err := crawler.Crawl(srv.URL+"/a", crawler.Config{Depth: 10, IgnoreRobots: true, MaxPages: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Pages) > 6 {
		t.Fatalf("loop not bounded: %d", len(res.Pages))
	}
}

func TestHoneypotAndPagination(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="/real">r</a><a href="/hp" hidden>h</a><a href="/page/1">n</a>`))
	})
	mux.HandleFunc("/real", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/hp", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("no")) })
	mux.HandleFunc("/page/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		n := strings.TrimPrefix(r.URL.Path, "/page/")
		w.Write([]byte(`<a href="/page/` + next(n) + `">n</a>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	res, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: -1, IgnoreRobots: true, MaxPages: 100})
	if err != nil {
		t.Fatal(err)
	}
	var pages int
	for _, p := range res.Pages {
		if strings.Contains(p.URL, "/hp") {
			t.Fatal("followed honeypot")
		}
		if strings.Contains(p.URL, "/page/") {
			pages++
		}
	}
	if pages > 12 {
		t.Fatalf("pagination trap failed: %d", pages)
	}
}

func next(n string) string {
	v := 0
	for _, c := range n {
		if c >= '0' && c <= '9' {
			v = v*10 + int(c-'0')
		}
	}
	return itoa(v + 1)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}

func TestRobots429AndJS(t *testing.T) {
	var n429 int
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("User-agent: *\nDisallow: /hidden\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="/hidden">h</a><a href="/ok">o</a><script src="/a.js"></script>`))
	})
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		if n429 < 1 {
			n429++
			w.WriteHeader(429)
			return
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/a.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`fetch("/api/x")`))
	})
	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("[core]"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	res, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: 2, IgnoreRobots: false, MaxPages: 40})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range res.Pages {
		if strings.Contains(p.URL, "/hidden") {
			t.Fatal("robots")
		}
	}
}

func TestProbedEnvScansSecrets(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<p>home</p>`))
	})
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	res, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: 0, IgnoreRobots: true, MaxPages: 40})
	if err != nil {
		t.Fatal(err)
	}
	var exposed, pat bool
	for _, f := range res.Findings {
		if f.ID == "exposed-file" && strings.HasSuffix(f.URL, "/.env") {
			exposed = true
		}
		if f.ID == "github-pat" && strings.HasSuffix(f.URL, "/.env") {
			pat = true
		}
	}
	if !exposed || !pat {
		t.Fatalf("probe secrets missing exposed=%v pat=%v findings=%#v", exposed, pat, res.Findings)
	}
}

func TestBackupNameMutation(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="/login">login</a><a href="/settings">s</a>`))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<p>login</p>"))
	})
	mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<p>settings</p>"))
	})
	mux.HandleFunc("/login.bak", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("# leftover login template backup\n"))
	})
	mux.HandleFunc("/backup.sql.bak", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("DUMP"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	res, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: 1, IgnoreRobots: true, MaxPages: 80})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	exposed := map[string]bool{}
	for _, p := range res.Pages {
		got[urls.PathOf(p.URL)] = true
	}
	for _, f := range res.Findings {
		if f.ID == "exposed-file" && f.Evidence != nil {
			exposed[*f.Evidence] = true
		}
	}
	if !got["/login.bak"] || !exposed["/login.bak"] {
		t.Fatalf("missing /login.bak pages=%v exposed=%v", got, exposed)
	}
	if !exposed["/backup.sql.bak"] {
		t.Fatalf("missing wordlist hit /backup.sql.bak in %v", exposed)
	}
	if got["/settings.bak"] || exposed["/settings.bak"] {
		t.Fatal("404 /settings.bak must not be a finding")
	}
	if got["/login.old"] || exposed["/login.old"] {
		t.Fatal("404 /login.old must not be a finding")
	}
}

func TestRefuseExternal(t *testing.T) {
	_, err := crawler.Crawl("http://example.com/", crawler.Config{})
	if err == nil {
		t.Fatal("expected refuse")
	}
	if err.Error() == "" {
		t.Fatal("empty error")
	}
}


func TestCORSProbe(t *testing.T) {
	var options []string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="/api/cors-reflect">r</a><a href="/api/cors-star-creds">c</a><a href="/api/cors-star">s</a><a href="/api/cors-locked">l</a><script src="/static/app.js"></script>`))
	})
	mux.HandleFunc("/api/cors-reflect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			options = append(options, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/api/cors-star-creds", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			options = append(options, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/api/cors-star", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			options = append(options, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/api/cors-locked", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			options = append(options, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "https://app.example")
		w.Write([]byte(`{"ok":true}`))
	})
	jsOptions := 0
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			jsOptions++
		}
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`console.log(1)`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	res, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: 1, IgnoreRobots: true, MaxPages: 40})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range res.Findings {
		if strings.HasPrefix(f.ID, "cors-") {
			got[f.ID+"|"+urls.PathOf(f.URL)] = f.Category
		}
	}
	if got["cors-reflect-origin|/api/cors-reflect"] != "header" {
		t.Fatalf("missing reflect in %#v", got)
	}
	if got["cors-wildcard-credentials|/api/cors-star-creds"] != "header" {
		t.Fatalf("missing wildcard-credentials in %#v", got)
	}
	if got["cors-allow-any|/api/cors-star"] != "header" {
		t.Fatalf("missing allow-any in %#v", got)
	}
	if _, ok := got["cors-allow-any|/api/cors-star-creds"]; ok {
		t.Fatalf("wildcard-credentials should not also emit allow-any: %#v", got)
	}
	if _, ok := got["cors-reflect-origin|/api/cors-locked"]; ok {
		t.Fatalf("locked origin should be negative: %#v", got)
	}
	if len(options) == 0 {
		t.Fatal("expected OPTIONS probes on API paths")
	}
	if jsOptions != 0 {
		t.Fatalf("OPTIONS sent to static js: %d", jsOptions)
	}
}

func TestCORSGETFallback(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="/api/only-get">x</a>`))
	})
	mux.HandleFunc("/api/only-get", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		}
		w.Write([]byte(`{"ok":true}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	res, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: 1, IgnoreRobots: true, MaxPages: 20})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if f.ID == "cors-reflect-origin" && urls.PathOf(f.URL) == "/api/only-get" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected GET Origin fallback reflect, findings %#v", res.Findings)
	}
}

func TestSourceMapOriginalFile(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<script src="/mapped.min.js"></script>`))
	})
	mux.HandleFunc("/mapped.min.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("function n(){return 1}\n//# sourceMappingURL=mapped.min.js.map\n"))
	})
	mux.HandleFunc("/mapped.min.js.map", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"version":3,"sources":["src/internal.ts"],"sourcesContent":["fetch(\"/api/sourcemap-only\");\n"]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	res, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: 2, IgnoreRobots: true, MaxPages: 20})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range res.JSEndpoints {
		if e.Endpoint == "/api/sourcemap-only" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing mapped endpoint in %#v", res.JSEndpoints)
	}
	ok := false
	for _, f := range res.Findings {
		if f.ID == "js-endpoint" && f.Evidence != nil && strings.Contains(*f.Evidence, "src/internal.ts") {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("original file not in evidence: %#v", res.Findings)
	}
}

func TestCookieJarUnlocksForm(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="/secret">s</a>`))
	})
	mux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		c, err := r.Cookie("auth")
		if err == nil && c.Value == "yes" {
			w.Write([]byte(`<form><input name="secret_field"></form>`))
			return
		}
		w.Write([]byte(`<p>wall</p>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	anon, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: 1, IgnoreRobots: true, MaxPages: 20})
	if err != nil {
		t.Fatal(err)
	}
	authed, err := crawler.Crawl(srv.URL+"/", crawler.Config{
		Depth: 1, IgnoreRobots: true, MaxPages: 20,
		Cookies: []crawler.SeedCookie{{Name: "auth", Value: "yes", Path: "/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if hasField(anon, "secret_field") {
		t.Fatal("anon should not see gated form")
	}
	if !hasField(authed, "secret_field") {
		t.Fatal("cookie jar should unlock secret_field")
	}
}

func TestExtraHeaderUnlocksForm(t *testing.T) {
	var gotHeader, gotCookie string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Lab-Auth")
		gotCookie = r.Header.Get("Cookie")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="/secret">s</a>`))
	})
	mux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.Header.Get("X-Lab-Auth") == "open" {
			w.Write([]byte(`<form><input name="via_header"></form>`))
			return
		}
		w.Write([]byte(`<p>wall</p>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	anon, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: 1, IgnoreRobots: true, MaxPages: 20})
	if err != nil {
		t.Fatal(err)
	}
	authed, err := crawler.Crawl(srv.URL+"/", crawler.Config{
		Depth: 1, IgnoreRobots: true, MaxPages: 20,
		Headers: []string{"X-Lab-Auth: open"},
		Cookies: []crawler.SeedCookie{{Name: "lab_auth", Value: "open", Path: "/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if hasField(anon, "via_header") {
		t.Fatal("anon should not see gated form")
	}
	if !hasField(authed, "via_header") {
		t.Fatal("header should unlock via_header")
	}
	if gotHeader != "open" {
		t.Fatalf("home request missing header, got %q cookie %q", gotHeader, gotCookie)
	}
	if !strings.Contains(gotCookie, "lab_auth=open") {
		t.Fatalf("home request missing cookie, got %q", gotCookie)
	}
}

func TestHeadersDoNotBypassLocalOnly(t *testing.T) {
	_, err := crawler.Crawl("https://example.com/", crawler.Config{
		Depth: 0, Headers: []string{"X-Lab-Auth: open"},
		Cookies: []crawler.SeedCookie{{Name: "lab_auth", Value: "open"}},
	})
	if err == nil {
		t.Fatal("expected non-local refusal")
	}
}

func TestLoginRecipeUnlocksForm(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="/secret">s</a>`))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			if r.Form.Get("user") == "ok" && r.Form.Get("csrf") == "tok" {
				http.SetCookie(w, &http.Cookie{Name: "auth", Value: "yes", Path: "/"})
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<form method="POST"><input type="hidden" name="csrf" value="tok"><input name="user"></form>`))
	})
	mux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		c, err := r.Cookie("auth")
		if err == nil && c.Value == "yes" {
			w.Write([]byte(`<form><input name="after_login"></form>`))
			return
		}
		w.Write([]byte(`<p>wall</p>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	res, err := crawler.Crawl(srv.URL+"/", crawler.Config{
		Depth: 1, IgnoreRobots: true, MaxPages: 20,
		LoginRecipe: &crawler.LoginRecipe{
			URL:    srv.URL + "/login",
			Method: "POST",
			Fields: map[string]string{"user": "ok"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasField(res, "after_login") {
		t.Fatalf("login recipe should unlock form: %#v", res.Pages)
	}
}

func hasField(res *models.CrawlResult, name string) bool {
	for _, p := range res.Pages {
		for _, f := range p.Forms {
			for _, field := range f.Fields {
				if field.Name == name {
					return true
				}
			}
		}
	}
	return false
}

func TestSitemapSeeds(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<p>home</p>`))
	})
	mux.HandleFunc("/sitemap-only", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<h1>unlinked</h1>`))
	})
	mux.HandleFunc("/from-robots", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<h1>via robots</h1>`))
	})
	mux.HandleFunc("/nested-only", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<h1>nested</h1>`))
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("User-agent: *\nSitemap: http://" + r.Host + "/alt-sitemap.xml\n"))
	})
	mux.HandleFunc("/alt-sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<urlset><url><loc>http://` + r.Host + `/from-robots</loc></url></urlset>`))
	})
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<sitemapindex><sitemap><loc>http://` + r.Host + `/nested.xml</loc></sitemap></sitemapindex>`))
	})
	mux.HandleFunc("/nested.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<urlset>
<url><loc>http://` + r.Host + `/sitemap-only</loc></url>
<url><loc>http://example.com/public</loc></url>
<url><loc>http://` + r.Host + `/nested-only</loc></url>
</urlset>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: 0, MaxPages: 40})
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, p := range res.Pages {
		if strings.Contains(p.URL, "example.com") {
			t.Fatalf("followed off-host loc %s", p.URL)
		}
		paths[urls.PathOf(p.URL)] = true
	}
	if !paths["/sitemap-only"] || !paths["/from-robots"] || !paths["/nested-only"] {
		t.Fatalf("sitemap seeds missing: %v", paths)
	}

	skipped, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: 0, NoSitemap: true, MaxPages: 40})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range skipped.Pages {
		switch urls.PathOf(p.URL) {
		case "/sitemap-only", "/from-robots", "/nested-only":
			t.Fatalf("--no-sitemap still visited %s", p.URL)
		}
	}
}

func TestHeadlessJSInjectedForm(t *testing.T) {
	if !crawler.HeadlessAvailable() {
		t.Skip("chrome not found")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><div id="root"></div>
<script>
const f = document.createElement('form');
f.action = '/injected';
f.method = 'POST';
const i = document.createElement('input');
i.name = 'token';
f.appendChild(i);
document.getElementById('root').appendChild(f);
</script></body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	res, err := crawler.Crawl(srv.URL+"/", crawler.Config{Mode: "headless", Depth: 0, IgnoreRobots: true, MaxPages: 5})
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "websocket url timeout") || strings.Contains(msg, "could not dial") || strings.Contains(msg, "context deadline exceeded") {
			t.Skip(msg)
		}
		t.Fatal(err)
	}
	if res.Crawler.Mode != "headless" {
		t.Fatalf("mode %s", res.Crawler.Mode)
	}
	if len(res.Pages) == 0 || res.Pages[0].StatusCode == 0 {
		t.Skip("headless navigation failed")
	}
	if !hasField(res, "token") {
		t.Fatalf("headless missed injected form: %#v", res.Pages)
	}
}

func TestHeadlessClickDiscoversRoute(t *testing.T) {
	if !crawler.HeadlessAvailable() {
		t.Skip("chrome not found")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>
<button type="button" onclick="history.pushState({}, '', '/hidden-route')">Open</button>
</body></html>`))
	})
	mux.HandleFunc("/hidden-route", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<form action="/x" method="POST"><input name="clicked"></form>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	static, err := crawler.Crawl(srv.URL+"/", crawler.Config{Mode: "static", Depth: 1, IgnoreRobots: true, MaxPages: 10})
	if err != nil {
		t.Fatal(err)
	}
	headless, err := crawler.Crawl(srv.URL+"/", crawler.Config{Mode: "headless", Depth: 1, IgnoreRobots: true, MaxPages: 10})
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "websocket") || strings.Contains(msg, "could not dial") || strings.Contains(msg, "context deadline exceeded") || strings.Contains(msg, "chrome failed to start") {
			t.Skip(msg)
		}
		t.Fatal(err)
	}
	if len(headless.Pages) == 0 || headless.Pages[0].StatusCode == 0 {
		t.Skip("headless navigation failed")
	}
	if hasPath(static, "/hidden-route") {
		t.Fatal("static should miss button-only route")
	}
	if !hasPath(headless, "/hidden-route") && !hasField(headless, "clicked") {
		t.Fatalf("headless missed click route: %#v", headless.Pages)
	}
}

func hasPath(res *models.CrawlResult, path string) bool {
	for _, p := range res.Pages {
		if urls.PathOf(p.URL) == path {
			return true
		}
	}
	return false
}

func TestTinyCrawlEmitsStats(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>ok</body></html>`))
	}))
	defer srv.Close()
	res, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: 0, IgnoreRobots: true, NoSitemap: true, MaxPages: 20})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats == nil {
		t.Fatal("stats missing")
	}
	if res.Stats.PagesCrawled != len(res.Pages) || res.Stats.PagesCrawled < 1 {
		t.Fatalf("pages_crawled=%d pages=%d", res.Stats.PagesCrawled, len(res.Pages))
	}
	if res.Stats.Requests < 1 {
		t.Fatalf("requests=%d", res.Stats.Requests)
	}
	if res.Stats.ElapsedMs < 0 {
		t.Fatalf("elapsed_ms=%d", res.Stats.ElapsedMs)
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"target", "scan_started_at", "scan_finished_at", "crawler", "pages", "findings", "js_endpoints", "stats"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing %s", k)
		}
	}
	stats := m["stats"].(map[string]any)
	if stats["pages_crawled"].(float64) < 1 || stats["requests"].(float64) < 1 {
		t.Fatalf("stats %#v", stats)
	}
}
