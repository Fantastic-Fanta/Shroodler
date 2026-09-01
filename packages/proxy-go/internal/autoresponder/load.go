package autoresponder

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/shroodler/proxy-go/internal/proxy"
	"gopkg.in/yaml.v3"
)

func Load(path string) ([]proxy.AutoRule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []proxy.AutoRule
	if err := yaml.Unmarshal(b, &rules); err != nil {
		return nil, fmt.Errorf("malformed rule file %s: %w", path, err)
	}
	dir := filepath.Dir(path)
	for i := range rules {
		r := &rules[i]
		if r.Match.URLPattern != "" {
			if _, err := regexp.Compile(r.Match.URLPattern); err != nil {
				return nil, fmt.Errorf("%s: invalid url_pattern on rule %d: %w", path, i+1, err)
			}
		}
		if r.Respond.BodyFile != "" {
			p := r.Respond.BodyFile
			if !filepath.IsAbs(p) {
				p = filepath.Join(dir, p)
			}
			bb, err := os.ReadFile(p)
			if err != nil {
				return nil, fmt.Errorf("%s: body_file: %w", path, err)
			}
			r.Respond.BodyBytes = bb
		} else {
			r.Respond.BodyBytes = []byte(r.Respond.Body)
		}
		if r.Respond.Status == 0 {
			r.Respond.Status = 200
		}
	}
	return rules, nil
}
