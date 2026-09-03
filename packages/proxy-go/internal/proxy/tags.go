package proxy

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"unicode"
)

func autoTags(sess *Session) []string {
	if sess == nil {
		return nil
	}
	var tags []string
	reqJSON := looksLikeJSONType(sess.Request.Headers)
	respJSON := false
	if sess.Response != nil {
		respJSON = looksLikeJSONType(sess.Response.Headers)
	}
	if reqJSON || respJSON {
		tags = append(tags, "json")
	}
	if sess.Response == nil {
		tags = append(tags, "no-response")
	} else if cls := statusClass(sess.Response.StatusCode); cls != "" {
		tags = append(tags, cls)
	}
	if sess.Response != nil && headerHas(sess.Response.Headers, "Set-Cookie") {
		tags = append(tags, "set-cookie")
	}
	if pathHasGraphQL(sess.Request.URL) || looksLikeGraphQL(requestBodyText(sess.Request)) {
		tags = append(tags, "graphql")
	}
	return tags
}

func mergeTags(existing, extra []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(existing)+len(extra))
	for _, t := range existing {
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	for _, t := range extra {
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

func statusClass(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500 && code < 600:
		return "5xx"
	default:
		return ""
	}
}

func looksLikeJSONType(headers map[string]string) bool {
	ct := headerGet(headers, "Content-Type")
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.ToLower(strings.TrimSpace(ct))
	return strings.Contains(ct, "json")
}

func headerGet(headers map[string]string, name string) string {
	if headers == nil {
		return ""
	}
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func headerHas(headers map[string]string, name string) bool {
	if headers == nil {
		return false
	}
	for k := range headers {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}

func pathHasGraphQL(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return strings.Contains(strings.ToLower(raw), "graphql")
	}
	return strings.Contains(strings.ToLower(u.Path), "graphql")
}

func requestBodyText(req HTTPMsg) string {
	if req.Body.Encoding == "base64" {
		b, err := base64.StdEncoding.DecodeString(req.Body.Content)
		if err != nil {
			return ""
		}
		return string(b)
	}
	return req.Body.Content
}

func looksLikeGraphQL(body string) bool {
	s := strings.TrimSpace(body)
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, "{") {
		var m map[string]any
		if json.Unmarshal([]byte(s), &m) == nil {
			q, ok := m["query"].(string)
			if ok && strings.TrimSpace(q) != "" {
				return true
			}
		}
	}
	return hasGraphQLOpPrefix(s)
}

func hasGraphQLOpPrefix(s string) bool {
	s = strings.TrimLeftFunc(s, unicode.IsSpace)
	lower := strings.ToLower(s)
	for _, op := range []string{"query", "mutation", "subscription"} {
		if !strings.HasPrefix(lower, op) {
			continue
		}
		rest := s[len(op):]
		if rest == "" {
			return true
		}
		r := rune(rest[0])
		if unicode.IsSpace(r) || r == '{' || r == '(' {
			return true
		}
	}
	return false
}
