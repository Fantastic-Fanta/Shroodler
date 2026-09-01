package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shroodler/crawler-go/internal/crawler"
	"github.com/shroodler/crawler-go/internal/models"
	"github.com/shroodler/crawler-go/internal/urls"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "crawl":
		os.Exit(cmdCrawl(os.Args[2:]))
	case "diff":
		os.Exit(cmdDiff(os.Args[2:]))
	case "report":
		os.Exit(cmdReport(os.Args[2:]))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "shroodler crawl <url> [--mode static|headless] [--depth N] [--output out.json] [--ignore-robots] [--allow-external]")
	fmt.Fprintln(os.Stderr, "shroodler report <findings.json> [--format html|csv] [--output out.html]")
	fmt.Fprintln(os.Stderr, "shroodler diff <findings.json> <expected_findings.json> [--pages-only]")
}

func cmdCrawl(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	target := args[0]
	cfg := crawler.Config{Depth: 5}
	var outPath string
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--depth":
			i++
			fmt.Sscanf(args[i], "%d", &cfg.Depth)
		case "--output", "-o":
			i++
			outPath = args[i]
		case "--ignore-robots":
			cfg.IgnoreRobots = true
		case "--allow-external":
			cfg.AllowExternal = true
		case "--mode":
			i++
			if args[i] == "headless" {
				fmt.Fprintln(os.Stderr, "headless mode is Python-only")
				return 2
			}
		}
	}
	res, err := crawler.Crawl(target, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	b, _ := json.MarshalIndent(res, "", "  ")
	if outPath != "" {
		_ = os.WriteFile(outPath, append(b, '\n'), 0o644)
	} else {
		fmt.Println(string(b))
	}
	return 0
}

func cmdDiff(args []string) int {
	pagesOnly := false
	var files []string
	for _, a := range args {
		if a == "--pages-only" {
			pagesOnly = true
			continue
		}
		files = append(files, a)
	}
	if len(files) != 2 {
		usage()
		return 2
	}
	actual := loadJSON(files[0])
	expected := loadJSON(files[1])
	errs := diffDocs(actual, expected, pagesOnly)
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, e)
		}
		return 1
	}
	fmt.Println("diff ok")
	return 0
}

func cmdReport(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	format := "html"
	var out string
	path := args[0]
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--format":
			i++
			format = args[i]
		case "--output", "-o":
			i++
			out = args[i]
		}
	}
	doc := loadJSON(path)
	var text string
	if format == "csv" {
		text = csvReport(doc)
	} else {
		text = htmlReport(doc)
	}
	if out != "" {
		_ = os.WriteFile(out, []byte(text), 0o644)
	} else {
		os.Stdout.WriteString(text)
	}
	return 0
}

func loadJSON(path string) map[string]any {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return m
}

func pathOf(u string) string {
	return urls.PathOf(u)
}

func diffDocs(actual, expected map[string]any, pagesOnly bool) []string {
	var errs []string
	actualPaths := map[string]bool{}
	if pages, ok := actual["pages"].([]any); ok {
		for _, p := range pages {
			m := p.(map[string]any)
			actualPaths[pathOf(fmt.Sprint(m["url"]))] = true
		}
	}
	if exp, ok := expected["expected_pages"].([]any); ok {
		for _, p := range exp {
			ps := fmt.Sprint(p)
			if !actualPaths[ps] {
				errs = append(errs, "missing page "+ps)
			}
		}
	}
	if pagesOnly {
		return errs
	}
	actualF := map[string]bool{}
	if findings, ok := actual["findings"].([]any); ok {
		for _, f := range findings {
			m := f.(map[string]any)
			k := fmt.Sprint(m["id"]) + "|" + pathOf(fmt.Sprint(m["url"]))
			actualF[k] = true
		}
	}
	if exp, ok := expected["expected_findings"].([]any); ok {
		for _, f := range exp {
			m := f.(map[string]any)
			k := fmt.Sprint(m["id"]) + "|" + pathOf(fmt.Sprint(m["url"]))
			if !actualF[k] {
				errs = append(errs, "missing finding "+fmt.Sprint(m["id"])+" at "+pathOf(fmt.Sprint(m["url"])))
			}
		}
	}
	if nf, ok := expected["expected_not_found"].([]any); ok {
		for _, f := range nf {
			m := f.(map[string]any)
			k := fmt.Sprint(m["id"]) + "|" + pathOf(fmt.Sprint(m["url"]))
			if actualF[k] {
				errs = append(errs, "unexpected finding "+fmt.Sprint(m["id"]))
			}
		}
	}
	return errs
}

func csvReport(doc map[string]any) string {
	var b strings.Builder
	b.WriteString("severity,id,category,url,description,evidence\n")
	if findings, ok := doc["findings"].([]any); ok {
		for _, f := range findings {
			m := f.(map[string]any)
			b.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s\n",
				m["severity"], m["id"], m["category"], m["url"], m["description"], m["evidence"]))
		}
	}
	return b.String()
}

func htmlReport(doc map[string]any) string {
	target := fmt.Sprint(doc["target"])
	n := 0
	if findings, ok := doc["findings"].([]any); ok {
		n = len(findings)
	}
	return fmt.Sprintf("<!DOCTYPE html><html><body><h1>Shroodler report</h1><p>Target: %s</p><p>%d findings</p></body></html>\n", target, n)
}

func init() {
	_ = filepath.Separator
	_ = models.CrawlResult{}
}
