package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
	"github.com/gorilla/websocket"
	"github.com/shroodler/proxy-go/internal/ca"
)

type Body struct {
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
}

type HTTPMsg struct {
	Method      string            `json:"method,omitempty"`
	URL         string            `json:"url,omitempty"`
	HTTPVersion string            `json:"http_version,omitempty"`
	StatusCode  int               `json:"status_code,omitempty"`
	Headers     map[string]string `json:"headers"`
	Body        Body              `json:"body"`
}

type Session struct {
	ID           string   `json:"id"`
	StartedAt    string   `json:"started_at"`
	FinishedAt   string   `json:"finished_at,omitempty"`
	ClientAddr   string   `json:"client_addr"`
	Request      HTTPMsg  `json:"request"`
	Response     *HTTPMsg `json:"response"`
	Tags         []string `json:"tags,omitempty"`
	Notes        *string  `json:"notes"`
	ReplayedFrom string   `json:"replayed_from,omitempty"`
}

type Server struct {
	Addr        string
	ControlAddr string
	RecordPath  string
	CA          *ca.Store
	Timeout     time.Duration

	mu          sync.Mutex
	sessions    map[string]*Session
	subs        []*websocket.Conn
	rules       []AutoRule
	breakpoints []BPRule
	paused      map[string]chan resume
	recordFile  *os.File
}

type resume struct {
	drop  bool
	edits map[string]any
}

type BPRule struct {
	Method     string `json:"method"`
	URLPattern string `json:"url_pattern"`
	Stage      string `json:"stage"`
}

type AutoRule struct {
	Match struct {
		Method     string `yaml:"method" json:"method"`
		URLPattern string `yaml:"url_pattern" json:"url_pattern"`
	} `yaml:"match" json:"match"`
	Respond struct {
		Status    int               `yaml:"status" json:"status"`
		Headers   map[string]string `yaml:"headers" json:"headers"`
		Body      string            `yaml:"body" json:"body"`
		BodyFile  string            `yaml:"body_file" json:"body_file"`
		BodyBytes []byte            `yaml:"-" json:"-"`
	} `yaml:"respond" json:"respond"`
}

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

func New(caStore *ca.Store) *Server {
	return &Server{
		Addr:        "127.0.0.1:8888",
		ControlAddr: "127.0.0.1:8890",
		CA:          caStore,
		Timeout:     5 * time.Minute,
		sessions:    map[string]*Session{},
		paused:      map[string]chan resume{},
	}
}

func (s *Server) Listen() (net.Listener, error) {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return nil, err
	}
	s.Addr = ln.Addr().String()
	return ln, nil
}

func (s *Server) ListenAddr() string { return s.Addr }

func (s *Server) Start() error {
	ln, err := s.Listen()
	if err != nil {
		return err
	}
	return s.StartOn(ln)
}

func (s *Server) StartOn(ln net.Listener) error {
	if s.RecordPath != "" && s.recordFile == nil {
		f, err := os.Create(s.RecordPath)
		if err != nil {
			return err
		}
		s.recordFile = f
	}
	go s.controlLoop()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(c)
	}
}

func (s *Server) controlLoop() {
	ln, err := net.Listen("tcp", s.ControlAddr)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.ControlAddr = ln.Addr().String()
	s.mu.Unlock()
	mux := http.NewServeMux()
	mux.HandleFunc("/control", func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		s.mu.Lock()
		s.subs = append(s.subs, ws)
		s.mu.Unlock()
		for {
			_, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			s.handleControl(ws, data)
		}
	})
	_ = http.Serve(ln, mux)
}

func (s *Server) handleControl(ws *websocket.Conn, data []byte) {
	var msg map[string]any
	if json.Unmarshal(data, &msg) != nil {
		return
	}
	switch msg["type"] {
	case "subscribe":
		// already added
	case "drop_breakpoint":
		id, _ := msg["session_id"].(string)
		s.resume(id, resume{drop: true})
	case "resume_breakpoint":
		id, _ := msg["session_id"].(string)
		edits, _ := msg["edits"].(map[string]any)
		s.resume(id, resume{edits: edits})
	case "replay_session":
		id, _ := msg["session_id"].(string)
		edits, _ := msg["edits"].(map[string]any)
		go s.ReplayID(id, edits)
	case "set_autoresponder_rules":
		raw, _ := json.Marshal(msg["rules"])
		var rules []AutoRule
		if json.Unmarshal(raw, &rules) == nil {
			for i := range rules {
				if len(rules[i].Respond.BodyBytes) == 0 {
					rules[i].Respond.BodyBytes = []byte(rules[i].Respond.Body)
				}
			}
			s.SetRules(rules)
		}
	case "set_breakpoints":
		raw, _ := json.Marshal(msg["rules"])
		var rules []BPRule
		if json.Unmarshal(raw, &rules) == nil {
			s.SetBreakpoints(rules)
		}
	case "compose_request":
		req, _ := msg["request"].(map[string]any)
		go s.Compose(req)
	}
}

func (s *Server) resume(id string, r resume) {
	s.mu.Lock()
	ch := s.paused[id]
	s.mu.Unlock()
	if ch != nil {
		ch <- r
	}
}

func (s *Server) emit(v any) {
	b, _ := json.Marshal(v)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ws := range s.subs {
		_ = ws.WriteMessage(websocket.TextMessage, b)
	}
}

func (s *Server) handleConn(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method == http.MethodConnect {
		s.handleConnect(c, br, req)
		return
	}
	s.handleHTTP(c, req, false)
}

func (s *Server) handleConnect(c net.Conn, br *bufio.Reader, req *http.Request) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	leaf, err := s.CA.Leaf(host)
	if err != nil {
		fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\n\r\nCA error: %v", err)
		return
	}
	_, _ = c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	tlsConn := tls.Server(c, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	tbr := bufio.NewReader(tlsConn)
	for {
		preq, err := http.ReadRequest(tbr)
		if err != nil {
			return
		}
		s.handleHTTP(tlsConn, preq, true)
	}
}

func (s *Server) handleHTTP(w io.Writer, req *http.Request, https bool) {
	sess := s.newSession(req, https)
	s.emit(map[string]any{"type": "session:new", "session": sess})
	if s.pauseIf(sess, req, nil, "request") {
		s.finish(sess, nil, []string{"dropped"})
		fmt.Fprintf(w, "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if rule := s.matchAuto(sess.Request.Method, sess.Request.URL); rule != nil {
		resp := &HTTPMsg{StatusCode: rule.Respond.Status, Headers: rule.Respond.Headers, Body: encodeBody(rule.Respond.BodyBytes, "text/plain")}
		if resp.StatusCode == 0 {
			resp.StatusCode = 200
		}
		if resp.Headers == nil {
			resp.Headers = map[string]string{}
		}
		sess.Tags = append(sess.Tags, "autoresponded")
		s.finish(sess, resp, sess.Tags)
		writeResp(w, resp)
		return
	}
	out, err := s.forward(req, https)
	if err != nil {
		sess.Tags = append(sess.Tags, "upstream_error")
		s.finish(sess, nil, sess.Tags)
		s.emit(map[string]any{"type": "error", "message": err.Error()})
		fmt.Fprintf(w, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if s.pauseIf(sess, req, out, "response") {
		s.finish(sess, out, []string{"dropped"})
		fmt.Fprintf(w, "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n")
		return
	}
	s.finish(sess, out, sess.Tags)
	writeResp(w, out)
}

func (s *Server) pauseIf(sess *Session, req *http.Request, resp *HTTPMsg, stage string) bool {
	if !s.matchBP(sess.Request.Method, sess.Request.URL, stage) {
		return false
	}
	ch := make(chan resume, 1)
	s.mu.Lock()
	s.paused[sess.ID] = ch
	s.mu.Unlock()
	s.emit(map[string]any{"type": "breakpoint:hit", "session_id": sess.ID, "stage": stage, "session": sess})
	timer := time.NewTimer(s.Timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		s.mu.Lock()
		delete(s.paused, sess.ID)
		s.mu.Unlock()
		if !r.drop {
			applyEdits(sess, req, resp, r.edits)
		}
		return r.drop
	case <-timer.C:
		s.mu.Lock()
		delete(s.paused, sess.ID)
		s.mu.Unlock()
		return true
	}
}

func applyEdits(sess *Session, req *http.Request, resp *HTTPMsg, edits map[string]any) {
	if edits == nil {
		return
	}
	if m, ok := edits["method"].(string); ok && req != nil {
		req.Method = m
		sess.Request.Method = m
	}
	if u, ok := edits["url"].(string); ok && req != nil {
		parsed, err := url.Parse(u)
		if err == nil {
			req.URL = parsed
			req.Host = parsed.Host
			sess.Request.URL = u
		}
	}
	if body, ok := edits["body"].(string); ok && req != nil {
		req.Body = io.NopCloser(strings.NewReader(body))
		req.ContentLength = int64(len(body))
		sess.Request.Body = Body{Encoding: "utf8", Content: body}
	}
	if headers, ok := edits["headers"].(map[string]any); ok {
		if req != nil && sess.Request.Headers == nil {
			sess.Request.Headers = map[string]string{}
		}
		for k, v := range headers {
			if req != nil {
				req.Header.Set(k, fmt.Sprint(v))
			}
			sess.Request.Headers[k] = fmt.Sprint(v)
			if resp != nil {
				if resp.Headers == nil {
					resp.Headers = map[string]string{}
				}
				resp.Headers[k] = fmt.Sprint(v)
			}
		}
	}
	if status, ok := edits["status"].(float64); ok && resp != nil {
		resp.StatusCode = int(status)
	}
	if rbody, ok := edits["response_body"].(string); ok && resp != nil {
		resp.Body = Body{Encoding: "utf8", Content: rbody}
	}
}

func (s *Server) matchBP(method, raw, stage string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.breakpoints {
		if r.Stage != stage {
			continue
		}
		if r.Method != "" && !strings.EqualFold(r.Method, method) {
			continue
		}
		if ok, _ := matchPat(r.URLPattern, raw); ok {
			return true
		}
	}
	return false
}

func (s *Server) matchAuto(method, raw string) *AutoRule {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rules {
		r := &s.rules[i]
		if r.Match.Method != "" && !strings.EqualFold(r.Match.Method, method) {
			continue
		}
		if ok, _ := matchPat(r.Match.URLPattern, raw); ok {
			return r
		}
	}
	return nil
}

func (s *Server) SetRules(rules []AutoRule) { s.mu.Lock(); s.rules = rules; s.mu.Unlock() }
func (s *Server) SetBreakpoints(b []BPRule) {
	s.mu.Lock()
	s.breakpoints = b
	s.mu.Unlock()
}

func (s *Server) newSession(req *http.Request, https bool) *Session {
	id := hex.EncodeToString(mustRand(8))
	scheme := "http"
	if https {
		scheme = "https"
	}
	u := req.URL.String()
	if req.URL.Host == "" && req.Host != "" {
		u = scheme + "://" + req.Host + req.URL.RequestURI()
	}
	body, _ := io.ReadAll(req.Body)
	req.Body = io.NopCloser(bytes.NewReader(body))
	hdrs := map[string]string{}
	for k, vs := range req.Header {
		hdrs[k] = strings.Join(vs, ", ")
	}
	sess := &Session{
		ID:         id,
		StartedAt:  time.Now().UTC().Format(time.RFC3339Nano),
		ClientAddr: "",
		Request: HTTPMsg{
			Method: req.Method, URL: u, HTTPVersion: req.Proto, Headers: hdrs,
			Body: encodeBody(body, hdrs["Content-Type"]),
		},
	}
	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()
	return sess
}

func (s *Server) finish(sess *Session, resp *HTTPMsg, tags []string) {
	sess.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	sess.Response = resp
	sess.Tags = tags
	s.emit(map[string]any{"type": "session:complete", "session": sess})
	if s.recordFile != nil {
		b, _ := json.Marshal(sess)
		s.mu.Lock()
		s.recordFile.Write(append(b, '\n'))
		s.mu.Unlock()
	}
}

func (s *Server) forward(req *http.Request, https bool) (*HTTPMsg, error) {
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: transport, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	outReq := req.Clone(req.Context())
	if outReq.URL.Scheme == "" {
		if https {
			outReq.URL.Scheme = "https"
		} else {
			outReq.URL.Scheme = "http"
		}
	}
	if outReq.URL.Host == "" {
		outReq.URL.Host = req.Host
	}
	outReq.RequestURI = ""
	resp, err := client.Do(outReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	enc := resp.Header.Get("Content-Encoding")
	decoded := decodeEnc(raw, enc)
	hdrs := map[string]string{}
	for k, vs := range resp.Header {
		hdrs[k] = strings.Join(vs, ", ")
	}
	return &HTTPMsg{StatusCode: resp.StatusCode, Headers: hdrs, HTTPVersion: resp.Proto, Body: encodeBody(decoded, hdrs["Content-Type"])}, nil
}

func (s *Server) ReplayID(id string, edits map[string]any) error {
	s.mu.Lock()
	sess := s.sessions[id]
	s.mu.Unlock()
	if sess == nil {
		s.emit(map[string]any{"type": "error", "message": "unknown session"})
		return fmt.Errorf("unknown session")
	}
	return s.ReplaySession(sess, edits)
}

func (s *Server) Compose(req map[string]any) error {
	method, _ := req["method"].(string)
	rawURL, _ := req["url"].(string)
	if method == "" {
		method = "GET"
	}
	headers := map[string]string{}
	if h, ok := req["headers"].(map[string]any); ok {
		for k, v := range h {
			headers[k] = fmt.Sprint(v)
		}
	}
	body, _ := req["body"].(string)
	base := &Session{
		Request: HTTPMsg{
			Method:  method,
			URL:     rawURL,
			Headers: headers,
			Body:    Body{Encoding: "utf8", Content: body},
		},
	}
	return s.ReplaySession(base, nil)
}

func (s *Server) ReplaySession(base *Session, edits map[string]any) error {
	method := base.Request.Method
	rawURL := base.Request.URL
	if edits != nil {
		if m, ok := edits["method"].(string); ok {
			method = m
		}
		if u, ok := edits["url"].(string); ok {
			rawURL = u
		}
	}
	body := []byte(base.Request.Body.Content)
	if base.Request.Body.Encoding == "base64" {
		body, _ = base64.StdEncoding.DecodeString(base.Request.Body.Content)
	}
	req, err := http.NewRequest(method, rawURL, bytes.NewReader(body))
	if err != nil {
		s.emit(map[string]any{"type": "error", "message": err.Error()})
		return err
	}
	for k, v := range base.Request.Headers {
		req.Header.Set(k, v)
	}
	https := strings.HasPrefix(rawURL, "https://")
	sess := s.newSession(req, https)
	sess.ReplayedFrom = base.ID
	sess.Tags = []string{"replayed_from:" + base.ID}
	out, err := s.forward(req, https)
	if err != nil {
		s.finish(sess, nil, []string{"upstream_error", "replayed_from:" + base.ID})
		s.emit(map[string]any{"type": "error", "message": err.Error()})
		return err
	}
	s.finish(sess, out, sess.Tags)
	return nil
}

func writeResp(w io.Writer, resp *HTTPMsg) {
	body := []byte(resp.Body.Content)
	if resp.Body.Encoding == "base64" {
		body, _ = base64.StdEncoding.DecodeString(resp.Body.Content)
	}
	fmt.Fprintf(w, "HTTP/1.1 %d OK\r\n", resp.StatusCode)
	for k, v := range resp.Headers {
		if strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		fmt.Fprintf(w, "%s: %s\r\n", k, v)
	}
	fmt.Fprintf(w, "Content-Length: %d\r\n\r\n", len(body))
	w.(io.Writer).Write(body)
}

func encodeBody(b []byte, ctype string) Body {
	if utf8.Valid(b) && (strings.Contains(ctype, "text") || strings.Contains(ctype, "json") || strings.Contains(ctype, "xml") || strings.Contains(ctype, "javascript") || ctype == "") {
		return Body{Encoding: "utf8", Content: string(b)}
	}
	return Body{Encoding: "base64", Content: base64.StdEncoding.EncodeToString(b)}
}

func decodeEnc(b []byte, enc string) []byte {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "gzip":
		r, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return b
		}
		out, err := io.ReadAll(r)
		if err != nil {
			return b
		}
		return out
	case "deflate":
		r, err := zlib.NewReader(bytes.NewReader(b))
		if err != nil {
			return b
		}
		out, err := io.ReadAll(r)
		if err != nil {
			return b
		}
		return out
	case "br":
		out, err := io.ReadAll(brotli.NewReader(bytes.NewReader(b)))
		if err != nil {
			return b
		}
		return out
	default:
		return b
	}
}

func matchPat(pat, raw string) (bool, error) {
	if pat == "" || pat == ".*" {
		return true, nil
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return strings.Contains(raw, pat), nil
	}
	return re.MatchString(raw), nil
}

func mustRand(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}
