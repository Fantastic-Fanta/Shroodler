package extractors

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/shroodler/crawler-go/internal/models"
	"golang.org/x/net/html"
)

func LoadCommentKeywords() []string {
	p := filepath.Join(RepoRoot(), "packages", "secret-patterns", "keywords", "html-comments.txt")
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func commentHits(text string, keywords []string) bool {
	low := strings.ToLower(text)
	for _, key := range keywords {
		if key != "" && strings.Contains(low, strings.ToLower(key)) {
			return true
		}
	}
	return false
}

func snippet(text string, limit int) string {
	compact := strings.Join(strings.Fields(text), " ")
	if len(compact) > limit {
		return compact[:limit]
	}
	return compact
}

func ExtractHTMLComments(body, pageURL string, rules []Rule) []models.Finding {
	if body == "" {
		return nil
	}
	keywords := LoadCommentKeywords()
	if len(keywords) == 0 {
		return nil
	}
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}
	var findings []models.Finding
	seen := map[string]bool{}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.CommentNode {
			text := strings.TrimSpace(n.Data)
			if text != "" && commentHits(text, keywords) {
				key := strings.ToLower(text)
				if !seen[key] {
					seen[key] = true
					cat := "verbose-error"
					if len(ScanSecrets(text, pageURL, rules)) > 0 {
						cat = "secret"
					}
					ev := snippet(text, 80)
					findings = append(findings, models.Finding{
						ID: "html-comment", Severity: "info", Category: cat,
						URL: pageURL, Description: "HTML comment contains leftover TODO or credential-like text",
						Evidence: &ev,
					})
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return findings
}

func ExtractMetaGenerator(body, pageURL string) []models.Finding {
	if body == "" {
		return nil
	}
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}
	var findings []models.Finding
	seen := map[string]bool{}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "meta" && strings.EqualFold(attr(n, "name"), "generator") {
			content := strings.TrimSpace(attr(n, "content"))
			if content != "" {
				key := strings.ToLower(content)
				if !seen[key] {
					seen[key] = true
					ev := snippet(content, 120)
					findings = append(findings, models.Finding{
						ID: "meta-generator", Severity: "info", Category: "header",
						URL: pageURL, Description: "meta generator tag discloses the application stack",
						Evidence: &ev,
					})
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return findings
}

func ExtractHTMLMarkup(body, pageURL string, rules []Rule) []models.Finding {
	var out []models.Finding
	out = append(out, ExtractHTMLComments(body, pageURL, rules)...)
	out = append(out, ExtractMetaGenerator(body, pageURL)...)
	return out
}
