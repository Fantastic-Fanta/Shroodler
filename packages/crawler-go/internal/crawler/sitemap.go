package crawler

import (
	"net/http"

	"github.com/shroodler/crawler-go/internal/extractors"
	"github.com/shroodler/crawler-go/internal/urls"
)

const maxSitemapDocs = 10

func discoverSitemapSeeds(client *http.Client, start, robotsBody string) (pages, docs []string) {
	pending := []string{}
	queued := map[string]bool{}

	offer := func(raw, base string) {
		resolved := urls.Normalize(base, raw)
		if resolved == "" || !urls.SameOrigin(resolved, start) {
			return
		}
		key := urls.CanonicalKey(resolved)
		if queued[key] {
			return
		}
		queued[key] = true
		pending = append(pending, resolved)
	}

	for _, sm := range extractors.ParseRobotsSitemaps(robotsBody) {
		offer(sm, start)
	}
	offer("/sitemap.xml", start)

	fetched := 0
	for len(pending) > 0 && fetched < maxSitemapDocs {
		smURL := pending[0]
		pending = pending[1:]
		if !urls.SameOrigin(smURL, start) {
			continue
		}
		fetched++
		body, status, _ := get(client, smURL)
		if status != 200 || body == "" {
			continue
		}
		docs = append(docs, smURL)
		urlLocs, nested := extractors.ParseSitemapXML(body)
		for _, loc := range nested {
			offer(loc, smURL)
		}
		for _, loc := range urlLocs {
			page := urls.Normalize(smURL, loc)
			if page != "" && urls.SameOrigin(page, start) {
				pages = append(pages, page)
			}
		}
	}
	return pages, docs
}
