package crawler_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shroodler/crawler-go/internal/crawler"
	"github.com/shroodler/crawler-go/internal/models"
)

func doc(target string, pageURLs ...string) *models.CrawlResult {
	pages := make([]models.Page, 0, len(pageURLs))
	for _, u := range pageURLs {
		pages = append(pages, models.Page{URL: u})
	}
	return &models.CrawlResult{Target: target, Pages: pages}
}

func TestAuthzDiffRefusesExternalWithoutAllowExternal(t *testing.T) {
	_, err := crawler.RunAuthzDiff(doc("https://example.com/"), crawler.AuthzDiffOptions{})
	if err == nil || !strings.Contains(err.Error(), "non-local") {
		t.Fatalf("expected a non-local error, got %v", err)
	}
}

func TestAuthzDiffAllowExternalBypassesGuard(t *testing.T) {
	res, err := crawler.RunAuthzDiff(doc("https://example.com/"), crawler.AuthzDiffOptions{AllowExternal: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Target != "https://example.com/" || len(res.Findings) != 0 {
		t.Fatalf("unexpected result %#v", res)
	}
}

func TestAuthzDiffFlagsBrokenAccessControlWhenAnonDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Cookie"), "session=admin-or-user") {
			w.Write([]byte("secret report"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	res, err := crawler.RunAuthzDiff(doc(srv.URL+"/", srv.URL+"/admin/report/1"), crawler.AuthzDiffOptions{
		CookieHeader: "session=admin-or-user",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFindingID(res.Findings, "authz-broken-access-control") {
		t.Fatalf("expected authz-broken-access-control, got %#v", res.Findings)
	}
}

func TestAuthzDiffNoFindingWhenAnonAlsoAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("public"))
	}))
	defer srv.Close()
	res, err := crawler.RunAuthzDiff(doc(srv.URL+"/", srv.URL+"/public/page"), crawler.AuthzDiffOptions{
		CookieHeader: "session=whatever",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %#v", res.Findings)
	}
}

func TestAuthzDiffNoFindingWhenLowerPrivDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Cookie"), "session=real-admin") {
			w.Write([]byte("secret"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	res, err := crawler.RunAuthzDiff(doc(srv.URL+"/", srv.URL+"/admin/only"), crawler.AuthzDiffOptions{
		CookieHeader: "session=not-admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %#v", res.Findings)
	}
}

func TestAuthzDiffNoAnonCheckReportsAnyReachableURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	res, err := crawler.RunAuthzDiff(doc(srv.URL+"/", srv.URL+"/somewhere"), crawler.AuthzDiffOptions{
		CookieHeader: "session=x",
		NoAnonCheck:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFindingID(res.Findings, "authz-still-accessible") {
		t.Fatalf("expected authz-still-accessible, got %#v", res.Findings)
	}
}

func TestAuthzDiffDedupesRepeatedURLs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	res, err := crawler.RunAuthzDiff(doc(srv.URL+"/", srv.URL+"/dup", srv.URL+"/dup"), crawler.AuthzDiffOptions{
		CookieHeader: "session=x",
		NoAnonCheck:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %#v", res.Findings)
	}
}

func TestAuthzDiffLoginRedirectCountsAsDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Cookie"), "session=admin-or-user") {
			w.Write([]byte("account page"))
			return
		}
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	res, err := crawler.RunAuthzDiff(doc(srv.URL+"/", srv.URL+"/account"), crawler.AuthzDiffOptions{
		CookieHeader: "session=admin-or-user",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFindingID(res.Findings, "authz-broken-access-control") {
		t.Fatalf("expected authz-broken-access-control, got %#v", res.Findings)
	}
}

func TestAuthzDiffOrdinaryRedirectIsNotTreatedAsDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Cookie"), "session=admin-or-user") {
			w.Write([]byte("report list"))
			return
		}
		w.Header().Set("Location", "/reports/")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	res, err := crawler.RunAuthzDiff(doc(srv.URL+"/", srv.URL+"/reports"), crawler.AuthzDiffOptions{
		CookieHeader: "session=admin-or-user",
	})
	if err != nil {
		t.Fatal(err)
	}
	if hasFindingID(res.Findings, "authz-broken-access-control") {
		t.Fatalf("ordinary redirect should not be denied: %#v", res.Findings)
	}
	if !hasFindingID(res.Findings, "authz-still-accessible") {
		t.Fatalf("expected authz-still-accessible, got %#v", res.Findings)
	}
}

func hasFindingID(findings []models.Finding, id string) bool {
	for _, f := range findings {
		if f.ID == id {
			return true
		}
	}
	return false
}
