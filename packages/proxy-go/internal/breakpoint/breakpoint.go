package breakpoint

import "github.com/shroodler/proxy-go/internal/proxy"

func Parse(method, pattern, stage string) proxy.BPRule {
	return proxy.BPRule{Method: method, URLPattern: pattern, Stage: stage}
}
