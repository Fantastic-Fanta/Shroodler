package crawler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shroodler/crawler-go/internal/crawler"
	"github.com/shroodler/crawler-go/internal/models"
	"github.com/shroodler/crawler-go/internal/urls"
)

func edgeKinds(edges []models.CrawlEdge, toPath string) map[string]bool {
	out := map[string]bool{}
	for _, e := range edges {
		if urls.PathOf(e.ToURL) == toPath {
			out[e.Kind] = true
		}
	}
	return out
}

func TestParentPageRecordsHTMLEdge(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<a href="/child">child</a>`))
	})
	mux.HandleFunc("/child", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`child`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	res, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: 1, IgnoreRobots: true, NoSitemap: true, MaxPages: 20})
	if err != nil {
		t.Fatal(err)
	}
	if got := edgeKinds(res.Edges, "/child"); len(got) != 1 || !got["html"] {
		t.Fatalf("edges %#v", res.Edges)
	}
}

func TestRedirectRecordsRedirectEdge(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/land")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/land", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`landed`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	res, err := crawler.Crawl(srv.URL+"/start", crawler.Config{Depth: 2, IgnoreRobots: true, NoSitemap: true, MaxPages: 20})
	if err != nil {
		t.Fatal(err)
	}
	if got := edgeKinds(res.Edges, "/land"); len(got) != 1 || !got["redirect"] {
		t.Fatalf("edges %#v", res.Edges)
	}
}

func TestFormActionRecordsFormEdge(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<form action="/save"><input name="q"></form>`))
	})
	mux.HandleFunc("/save", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`saved`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	res, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: 1, IgnoreRobots: true, NoSitemap: true, MaxPages: 20})
	if err != nil {
		t.Fatal(err)
	}
	if got := edgeKinds(res.Edges, "/save"); len(got) != 1 || !got["form"] {
		t.Fatalf("edges %#v", res.Edges)
	}
}

func TestCrawlJSONWithoutEdgesStillLoads(t *testing.T) {
	raw := []byte(`{"target":"http://127.0.0.1/","pages":[],"findings":[],"js_endpoints":[]}`)
	var doc models.CrawlResult
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Edges) != 0 {
		t.Fatalf("expected no edges, got %#v", doc.Edges)
	}
}
