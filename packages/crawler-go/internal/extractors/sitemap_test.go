package extractors

import "testing"

func TestParseRobotsSitemaps(t *testing.T) {
	body := "User-agent: *\nDisallow: /hidden\nSitemap: http://127.0.0.1:8081/sitemap.xml\n" +
		"sitemap: /alt.xml\n# Sitemap: http://evil.example/ignore.xml\nSitemap:\n" +
		"Sitemap: http://127.0.0.1:8081/other.xml # comment\n"
	got := ParseRobotsSitemaps(body)
	if len(got) != 3 {
		t.Fatalf("got %#v", got)
	}
	if got[0] != "http://127.0.0.1:8081/sitemap.xml" || got[1] != "/alt.xml" || got[2] != "http://127.0.0.1:8081/other.xml" {
		t.Fatalf("got %#v", got)
	}
	if ParseRobotsSitemaps("") != nil && len(ParseRobotsSitemaps("")) != 0 {
		t.Fatal("empty")
	}
	if len(ParseRobotsSitemaps("User-agent: *\nDisallow: /\n")) != 0 {
		t.Fatal("no sitemap lines")
	}
}

func TestParseSitemapXML(t *testing.T) {
	urlset := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://127.0.0.1/a</loc></url>
  <url><loc>http://127.0.0.1/b</loc></url>
</urlset>`
	urls, nested := ParseSitemapXML(urlset)
	if len(urls) != 2 || urls[0] != "http://127.0.0.1/a" || urls[1] != "http://127.0.0.1/b" {
		t.Fatalf("urls %#v", urls)
	}
	if len(nested) != 0 {
		t.Fatalf("nested %#v", nested)
	}

	index := `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>http://127.0.0.1/sitemap-pages.xml</loc></sitemap>
</sitemapindex>`
	urls, nested = ParseSitemapXML(index)
	if len(urls) != 0 {
		t.Fatalf("index urls %#v", urls)
	}
	if len(nested) != 1 || nested[0] != "http://127.0.0.1/sitemap-pages.xml" {
		t.Fatalf("nested %#v", nested)
	}
}

func TestParseSitemapXMLMalformed(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v", r)
		}
	}()
	u, n := ParseSitemapXML("")
	if len(u) != 0 || len(n) != 0 {
		t.Fatalf("%v %v", u, n)
	}
	u, n = ParseSitemapXML("not xml at all <<>>")
	if len(u) != 0 || len(n) != 0 {
		t.Fatalf("garbage %v %v", u, n)
	}
	ParseSitemapXML("<urlset><url><loc>http://127.0.0.1/x</loc>")
	ParseSitemapXML("<notclosed")
}
