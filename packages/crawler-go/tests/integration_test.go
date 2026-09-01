package crawler_test

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/shroodler/crawler-go/internal/crawler"
	"github.com/shroodler/crawler-go/internal/urls"
)

func TestApp1Pages(t *testing.T) {
	resp, err := http.Get("http://127.0.0.1:8081/")
	if err != nil {
		t.Skip("app1 not running")
	}
	resp.Body.Close()
	res, err := crawler.Crawl("http://127.0.0.1:8081", crawler.Config{Depth: 5, MaxPages: 80})
	if err != nil {
		t.Fatal(err)
	}
	need := []string{"/", "/login", "/dashboard", "/settings"}
	have := map[string]bool{}
	for _, p := range res.Pages {
		have[urls.PathOf(p.URL)] = true
	}
	for _, n := range need {
		if !have[n] {
			t.Fatalf("missing %s in %v", n, have)
		}
	}
	b, _ := json.Marshal(res)
	if !json.Valid(b) {
		t.Fatal("invalid json")
	}
	_ = os.Stdout
}

func TestApp3Bounded(t *testing.T) {
	resp, err := http.Get("http://127.0.0.1:8083/")
	if err != nil {
		t.Skip("app3 not running")
	}
	resp.Body.Close()
	res, err := crawler.Crawl("http://127.0.0.1:8083", crawler.Config{Depth: -1, MaxPages: 80})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Pages) > 80 {
		t.Fatal(len(res.Pages))
	}
}
