package crawler_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shroodler/crawler-go/internal/crawler"
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

func TestRefuseExternal(t *testing.T) {
	_, err := crawler.Crawl("http://example.com/", crawler.Config{})
	if err == nil {
		t.Fatal("expected refuse")
	}
}
