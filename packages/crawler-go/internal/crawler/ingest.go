package crawler

import (
	"strings"
	"time"

	"github.com/shroodler/crawler-go/internal/extractors"
	"github.com/shroodler/crawler-go/internal/models"
	"github.com/shroodler/crawler-go/internal/sessions"
	"github.com/shroodler/crawler-go/internal/urls"
)

func Ingest(path, target string, allowExternal bool) (*models.CrawlResult, error) {
	list, err := sessions.LoadJSONL(path)
	if err != nil {
		return nil, err
	}
	return ingestList(list, target, allowExternal)
}

func ingestList(list []sessions.Session, target string, allowExternal bool) (*models.CrawlResult, error) {
	started := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	t0 := time.Now()
	inferred := target
	if inferred == "" {
		for _, s := range list {
			if s.Request.URL != "" && strings.Contains(s.Request.URL, "://") {
				inferred = urls.Origin(s.Request.URL)
				break
			}
		}
	}
	if inferred == "" {
		return nil, errString("no sessions to ingest; pass --target or capture at least one HTTP session")
	}
	if !strings.Contains(inferred, "://") {
		inferred = "http://" + inferred
	}
	if !allowExternal && !urls.IsLocal(inferred) {
		return nil, errNonLocal
	}
	rules := extractors.LoadSecretRules()
	last := map[string]sessions.Session{}
	var order []string
	var extra []models.Finding
	for _, s := range list {
		m := strings.ToUpper(s.Request.Method)
		if m == "CONNECT" || m == "OPTIONS" || s.Request.URL == "" {
			continue
		}
		if !urls.SameOrigin(s.Request.URL, inferred) {
			continue
		}
		blob := s.Request.Body.Text()
		for k, v := range s.Request.Headers {
			blob += "\n" + k + ": " + v
		}
		if strings.TrimSpace(blob) != "" {
			extra = append(extra, extractors.ScanSecrets(blob, s.Request.URL, rules)...)
		}
		if s.Response == nil {
			continue
		}
		key := urls.CanonicalKey(s.Request.URL)
		if _, ok := last[key]; !ok {
			order = append(order, key)
		}
		last[key] = s
	}
	var pages []models.Page
	var findings []models.Finding
	var endpoints []models.JSEndpoint
	findings = append(findings, extra...)
	for _, key := range order {
		res := fetchFromSession(last[key])
		page, f, eps := pageFrom(res, rules, nil)
		pages = append(pages, page)
		findings = append(findings, f...)
		endpoints = append(endpoints, eps...)
	}
	if pages == nil {
		pages = []models.Page{}
	}
	finished := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	return &models.CrawlResult{
		Target:         inferred,
		ScanStartedAt:  started,
		ScanFinishedAt: finished,
		Crawler:        models.CrawlerInfo{Name: "shroodler-go", Version: version, Mode: "ingest"},
		Pages:          pages,
		Findings:       dedupeF(findings),
		JSEndpoints:    endpoints,
		Stats: &models.CrawlStats{
			PagesCrawled: len(pages),
			Requests:     len(order),
			ElapsedMs:    time.Since(t0).Milliseconds(),
		},
	}, nil
}

func fetchFromSession(s sessions.Session) fetchResult {
	hdrs := map[string]string{}
	status := 0
	body := ""
	var setCookies []string
	if s.Response != nil {
		status = s.Response.StatusCode
		body = s.Response.Body.Text()
		for k, v := range s.Response.Headers {
			hdrs[k] = v
		}
		setCookies = sessions.SplitSetCookie(sessions.HeaderGet(s.Response.Headers, "Set-Cookie"))
	}
	if setCookies == nil {
		setCookies = []string{}
	}
	return fetchResult{URL: s.Request.URL, Status: status, Headers: hdrs, Body: body, SetCookies: setCookies}
}
