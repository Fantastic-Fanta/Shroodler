package crawler

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/shroodler/crawler-go/internal/urls"
)

type headlessSession struct {
	allocCancel context.CancelFunc
	cancel      context.CancelFunc
	ctx         context.Context
	cookies     []SeedCookie
	headers     map[string]string
	origin      string
	dataDir     string
}

func HeadlessAvailable() bool {
	_, err := lookChrome()
	return err == nil
}

func lookChrome() (string, error) {
	candidates := []string{
		os.Getenv("CHROME_PATH"),
		os.Getenv("GOOGLE_CHROME_BIN"),
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		"/usr/bin/google-chrome",
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
	}
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("headless mode requires Chrome or Chromium on PATH (or CHROME_PATH)")
}

func newHeadless(origin string, cookies []SeedCookie, extra map[string]string) (*headlessSession, error) {
	path, err := lookChrome()
	if err != nil {
		return nil, err
	}
	dataDir, err := os.MkdirTemp("", "shroodler-chrome-*")
	if err != nil {
		return nil, err
	}
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(path),
		chromedp.UserDataDir(dataDir),
		chromedp.Flag("headless", "new"),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancel := chromedp.NewContext(allocCtx)
	runCtx, runCancel := context.WithTimeout(ctx, 20*time.Second)
	defer runCancel()
	if err := chromedp.Run(runCtx); err != nil {
		cancel()
		allocCancel()
		_ = os.RemoveAll(dataDir)
		return nil, err
	}
	return &headlessSession{allocCancel: allocCancel, cancel: cancel, ctx: ctx, cookies: cookies, headers: extra, origin: origin, dataDir: dataDir}, nil
}

func (h *headlessSession) close() {
	if h.cancel != nil {
		h.cancel()
	}
	if h.allocCancel != nil {
		h.allocCancel()
	}
	if h.dataDir != "" {
		_ = os.RemoveAll(h.dataDir)
	}
}

func (h *headlessSession) applyCookies(ctx context.Context) error {
	for _, c := range h.cookies {
		expr := network.SetCookie(c.Name, c.Value).WithURL(h.origin)
		if c.Path != "" {
			expr = expr.WithPath(c.Path)
		}
		if c.Domain != "" {
			expr = expr.WithDomain(c.Domain)
		}
		if err := expr.Do(ctx); err != nil {
			return err
		}
	}
	return nil
}

const clickEnumJS = `(() => {
  const found = [];
  const seen = new Set();
  const remember = (u) => {
    if (!u || seen.has(u)) return;
    seen.add(u);
    found.push(u);
  };
  remember(location.href);
  window.__shroodlerRoutes = window.__shroodlerRoutes || [];
  const origPush = history.pushState.bind(history);
  const origReplace = history.replaceState.bind(history);
  history.pushState = function (...args) {
    origPush(...args);
    window.__shroodlerRoutes.push(location.href);
  };
  history.replaceState = function (...args) {
    origReplace(...args);
    window.__shroodlerRoutes.push(location.href);
  };
  const candidates = [];
  for (const el of document.querySelectorAll("a[href], button, [role=button]")) {
    const style = getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden" || el.hidden) continue;
    if (el.closest("[hidden], .honeypot, [aria-hidden='true']")) continue;
    const type = (el.getAttribute("type") || "").toLowerCase();
    if (type === "submit" || type === "reset") continue;
    if (el.tagName === "BUTTON" && type !== "button" && el.closest("form")) continue;
    candidates.push(el);
    if (candidates.length >= 8) break;
  }
  const original = location.href;
  for (const el of candidates) {
    try { el.click(); } catch (e) {}
    remember(location.href);
    for (const extra of (window.__shroodlerRoutes || [])) remember(extra);
    if (location.href !== original) {
      history.pushState({}, "", original);
    }
  }
  return found.filter((u) => u !== original);
})()`

func (h *headlessSession) fetch(raw string) fetchResult {
	tabCtx, tabCancel := chromedp.NewContext(h.ctx)
	defer tabCancel()
	ctx, cancel := context.WithTimeout(tabCtx, 20*time.Second)
	defer cancel()

	var status int64
	var ctype string
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		e, ok := ev.(*network.EventResponseReceived)
		if !ok || e.Type != network.ResourceTypeDocument {
			return
		}
		status = e.Response.Status
		for k, v := range e.Response.Headers {
			if strings.EqualFold(k, "content-type") {
				ctype = fmt.Sprint(v)
			}
		}
	})

	var html, loc string
	var cookies []*network.Cookie
	var discovered []string
	err := chromedp.Run(ctx,
		network.Enable(),
		chromedp.ActionFunc(func(ctx context.Context) error {
			if len(h.headers) == 0 {
				return nil
			}
			hd := network.Headers{}
			for k, v := range h.headers {
				hd[k] = v
			}
			return network.SetExtraHTTPHeaders(hd).Do(ctx)
		}),
		chromedp.ActionFunc(func(ctx context.Context) error {
			return h.applyCookies(ctx)
		}),
		chromedp.Navigate(raw),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(400*time.Millisecond),
		chromedp.ActionFunc(func(ctx context.Context) error {
			res, exp, err := runtime.Evaluate(clickEnumJS).WithReturnByValue(true).Do(ctx)
			if err != nil || exp != nil || res == nil {
				return nil
			}
			var found []string
			_ = json.Unmarshal(res.Value, &found)
			for _, part := range found {
				if part != "" && urls.SameOrigin(part, raw) {
					discovered = append(discovered, part)
				}
			}
			return nil
		}),
		chromedp.Location(&loc),
		chromedp.OuterHTML("html", &html, chromedp.ByQuery),
		chromedp.ActionFunc(func(ctx context.Context) error {
			c, err := network.GetCookies().Do(ctx)
			cookies = c
			return err
		}),
	)
	if err != nil {
		return fetchResult{URL: raw}
	}
	if loc == "" {
		loc = raw
	}
	headers := map[string]string{"Content-Type": "text/html"}
	if ctype != "" {
		headers["Content-Type"] = ctype
	}
	var setCookies []string
	for _, c := range cookies {
		parts := []string{c.Name + "=" + c.Value}
		if c.Secure {
			parts = append(parts, "Secure")
		}
		if c.HTTPOnly {
			parts = append(parts, "HttpOnly")
		}
		if string(c.SameSite) != "" {
			parts = append(parts, "SameSite="+string(c.SameSite))
		}
		setCookies = append(setCookies, strings.Join(parts, "; "))
	}
	st := int(status)
	if st == 0 {
		st = 200
	}
	return fetchResult{URL: loc, Status: st, Headers: headers, Body: html, SetCookies: setCookies, Discovered: discovered}
}
