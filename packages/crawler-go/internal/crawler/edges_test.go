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
	if len(doc.Unfetched) != 0 {
		t.Fatalf("expected no unfetched, got %#v", doc.Unfetched)
	}
}

func TestEarlyStopListsLinkedURLNotOpened(t *testing.T) {
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

	stopped, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: 1, IgnoreRobots: true, NoSitemap: true, MaxPages: 1})
	if err != nil {
		t.Fatal(err)
	}
	if stopped.Stats == nil || stopped.Stats.StoppedReason != "max-pages" {
		t.Fatalf("stats %#v", stopped.Stats)
	}
	if len(stopped.Unfetched) != 1 || urls.PathOf(stopped.Unfetched[0]) != "/child" {
		t.Fatalf("unfetched %#v", stopped.Unfetched)
	}
	raw, err := json.Marshal(stopped)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["unfetched"]; !ok {
		t.Fatal("early stop omitted unfetched")
	}

	finished, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: 1, IgnoreRobots: true, NoSitemap: true, MaxPages: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(finished.Unfetched) != 0 {
		t.Fatalf("finished crawl listed %#v", finished.Unfetched)
	}
	finishedRaw, err := json.Marshal(finished)
	if err != nil {
		t.Fatal(err)
	}
	var finishedDoc map[string]any
	if err := json.Unmarshal(finishedRaw, &finishedDoc); err != nil {
		t.Fatal(err)
	}
	if _, ok := finishedDoc["unfetched"]; ok {
		t.Fatalf("finished crawl json has unfetched: %s", finishedRaw)
	}
}
