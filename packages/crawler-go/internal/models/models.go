package models

type CrawlerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Mode    string `json:"mode"`
}

type FormField struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Hidden   bool   `json:"hidden"`
	Disabled *bool  `json:"disabled,omitempty"`
	Readonly *bool  `json:"readonly,omitempty"`
}

type Form struct {
	Action  string      `json:"action"`
	Method  string      `json:"method"`
	Fields  []FormField `json:"fields"`
	Enctype *string     `json:"enctype,omitempty"`
}

type Cookie struct {
	Name     string  `json:"name"`
	Secure   bool    `json:"secure"`
	HTTPOnly bool    `json:"http_only"`
	SameSite *string `json:"same_site"`
}

type HeaderAnalysis struct {
	Present []string `json:"present"`
	Missing []string `json:"missing"`
}

type Page struct {
	URL        string         `json:"url"`
	StatusCode int            `json:"status_code"`
	Forms      []Form         `json:"forms"`
	Params     []string       `json:"params"`
	Cookies    []Cookie       `json:"cookies"`
	Headers    HeaderAnalysis `json:"headers"`
	JSFiles    []string       `json:"js_files"`
}

type Finding struct {
	ID          string  `json:"id"`
	Severity    string  `json:"severity"`
	Category    string  `json:"category"`
	URL         string  `json:"url"`
	Description string  `json:"description"`
	Evidence    *string `json:"evidence"`
}

type JSEndpoint struct {
	Source   string `json:"source"`
	Endpoint string `json:"endpoint"`
}

type CrawlStats struct {
	PagesCrawled int   `json:"pages_crawled"`
	Requests     int   `json:"requests"`
	ElapsedMs    int64 `json:"elapsed_ms"`
}

type CrawlResult struct {
	Target         string       `json:"target"`
	ScanStartedAt  string       `json:"scan_started_at"`
	ScanFinishedAt string       `json:"scan_finished_at"`
	Crawler        CrawlerInfo  `json:"crawler"`
	Pages          []Page       `json:"pages"`
	Findings       []Finding    `json:"findings"`
	JSEndpoints    []JSEndpoint `json:"js_endpoints"`
	Stats          *CrawlStats  `json:"stats,omitempty"`
}
