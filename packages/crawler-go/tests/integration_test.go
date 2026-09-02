package crawler_test

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/shroodler/crawler-go/internal/crawler"
	"github.com/shroodler/crawler-go/internal/models"
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
	need := []string{"/", "/login", "/dashboard", "/settings", "/login.bak"}
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

func TestApp1LabGatedAuth(t *testing.T) {
	resp, err := http.Get("http://127.0.0.1:8081/")
	if err != nil {
		t.Skip("app1 not running")
	}
	resp.Body.Close()
	gated := "http://127.0.0.1:8081/lab-gated"
	anon, err := crawler.Crawl("http://127.0.0.1:8081", crawler.Config{
		Depth: 0, IgnoreRobots: true, MaxPages: 20, Seeds: []string{gated},
	})
	if err != nil {
		t.Fatal(err)
	}
	viaCookie, err := crawler.Crawl("http://127.0.0.1:8081", crawler.Config{
		Depth: 0, IgnoreRobots: true, MaxPages: 20, Seeds: []string{gated},
		Cookies: []crawler.SeedCookie{{Name: "lab_auth", Value: "open", Path: "/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	viaHeader, err := crawler.Crawl("http://127.0.0.1:8081", crawler.Config{
		Depth: 0, IgnoreRobots: true, MaxPages: 20, Seeds: []string{gated},
		Headers: []string{"X-Lab-Auth: open"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if pageHasField(anon, "lab_gated_field") {
		t.Fatal("anon should not see lab_gated_field")
	}
	if !pageHasField(viaCookie, "lab_gated_field") {
		t.Fatal("cookie should unlock lab_gated_field")
	}
	if !pageHasField(viaHeader, "lab_gated_field") {
		t.Fatal("header should unlock lab_gated_field")
	}
}

func TestApp1LoginRecipeProfile(t *testing.T) {
	resp, err := http.Get("http://127.0.0.1:8081/")
	if err != nil {
		t.Skip("app1 not running")
	}
	resp.Body.Close()
	recipe, err := crawler.LoadLoginRecipe(filepath.Join(repoRoot(), "packages", "target-apps", "app1-server-rendered", "login-recipe.json"))
	if err != nil {
		t.Fatal(err)
	}
	anon, err := crawler.Crawl("http://127.0.0.1:8081", crawler.Config{Depth: 3, IgnoreRobots: true, MaxPages: 80})
	if err != nil {
		t.Fatal(err)
	}
	authed, err := crawler.Crawl("http://127.0.0.1:8081", crawler.Config{
		Depth: 3, IgnoreRobots: true, MaxPages: 80, LoginRecipe: recipe,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pageHasPath(anon, "/profile") {
		t.Fatal("anon crawl should not reach /profile")
	}
	if !pageHasPath(authed, "/profile") {
		t.Fatal("login recipe should discover /profile")
	}
}

func pageHasPath(res *models.CrawlResult, path string) bool {
	if res == nil {
		return false
	}
	for _, p := range res.Pages {
		if urls.PathOf(p.URL) == path {
			return true
		}
	}
	return false
}

func pageHasField(res *models.CrawlResult, name string) bool {
	if res == nil {
		return false
	}
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

func repoRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
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
