// Package har converts Shroodler proxy session JSONL to HTTP Archive 1.2 and back.
// JSONL remains the canonical capture format; HAR is browser interchange only.
package har

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/shroodler/proxy-go/internal/proxy"
)

const (
	harVersion     = "1.2"
	creatorName    = "shroodler-proxy"
	creatorVersion = "1.0"
)

// File is a HAR 1.2 document.
type File struct {
	Log Log `json:"log"`
}

type Log struct {
	Version string  `json:"version"`
	Creator Creator `json:"creator"`
	Entries []Entry `json:"entries"`
}

type Creator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Entry struct {
	StartedDateTime string   `json:"startedDateTime"`
	Time            float64  `json:"time"`
	Request         Request  `json:"request"`
	Response        Response `json:"response"`
	Cache           struct{} `json:"cache"`
	Timings         Timings  `json:"timings"`

	// Shroodler extensions (browsers ignore unknown fields).
	SessionID    string   `json:"_sessionId,omitempty"`
	ClientAddr   string   `json:"_clientAddr,omitempty"`
	Tags         []string `json:"_tags,omitempty"`
	Notes        string   `json:"_notes,omitempty"`
	ReplayedFrom string   `json:"_replayedFrom,omitempty"`
}

type Timings struct {
	Blocked float64 `json:"blocked"`
	DNS     float64 `json:"dns"`
	Connect float64 `json:"connect"`
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
	SSL     float64 `json:"ssl"`
}

type NameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Request struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Cookies     []NameValue `json:"cookies"`
	Headers     []NameValue `json:"headers"`
	QueryString []NameValue `json:"queryString"`
	PostData    *PostData   `json:"postData,omitempty"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
}

type PostData struct {
	MimeType string  `json:"mimeType"`
	Text     string  `json:"text,omitempty"`
	Encoding string  `json:"encoding,omitempty"` // Chrome extension; HAR 1.2 has no postData encoding
	Params   []Param `json:"params,omitempty"`
}

type Param struct {
	Name        string `json:"name"`
	Value       string `json:"value,omitempty"`
	FileName    string `json:"fileName,omitempty"`
	ContentType string `json:"contentType,omitempty"`
}

type Response struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Cookies     []NameValue `json:"cookies"`
	Headers     []NameValue `json:"headers"`
	Content     Content     `json:"content"`
	RedirectURL string      `json:"redirectURL"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
}

type Content struct {
	Size        int    `json:"size"`
	MimeType    string `json:"mimeType"`
	Text        string `json:"text,omitempty"`
	Encoding    string `json:"encoding,omitempty"`
	Compression int    `json:"compression,omitempty"`
}

// ExportFile reads canonical session JSONL and writes a HAR 1.2 document.
func ExportFile(jsonlPath, harPath string) error {
	in, err := os.Open(jsonlPath)
	if err != nil {
		return err
	}
	defer in.Close()
	sessions, err := ReadJSONL(in)
	if err != nil {
		return err
	}
	out, err := os.Create(harPath)
	if err != nil {
		return err
	}
	defer out.Close()
	return WriteHAR(out, sessions)
}

// ImportFile reads a HAR 1.2 document and writes canonical session JSONL.
func ImportFile(harPath, jsonlPath string) error {
	in, err := os.Open(harPath)
	if err != nil {
		return err
	}
	defer in.Close()
	sessions, err := ReadHAR(in)
	if err != nil {
		return err
	}
	out, err := os.Create(jsonlPath)
	if err != nil {
		return err
	}
	defer out.Close()
	return WriteJSONL(out, sessions)
}

func ReadJSONL(r io.Reader) ([]proxy.Session, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	var sessions []proxy.Session
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var sess proxy.Session
		if err := json.Unmarshal([]byte(raw), &sess); err != nil {
			return nil, fmt.Errorf("jsonl line %d: %w", line, err)
		}
		sessions = append(sessions, sess)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return sessions, nil
}

func WriteJSONL(w io.Writer, sessions []proxy.Session) error {
	enc := json.NewEncoder(w)
	for _, sess := range sessions {
		if err := enc.Encode(sess); err != nil {
			return err
		}
	}
	return nil
}

func WriteHAR(w io.Writer, sessions []proxy.Session) error {
	f := File{Log: SessionsToLog(sessions)}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(f)
}

func ReadHAR(r io.Reader) ([]proxy.Session, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	raw = bytesBOM(raw)
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("har: %w", err)
	}
	if f.Log.Entries == nil && f.Log.Version == "" {
		return nil, fmt.Errorf("har: missing log (not a HAR document)")
	}
	return LogToSessions(f.Log), nil
}

func bytesBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}

func SessionsToLog(sessions []proxy.Session) Log {
	log := Log{
		Version: harVersion,
		Creator: Creator{Name: creatorName, Version: creatorVersion},
		Entries: make([]Entry, 0, len(sessions)),
	}
	for _, sess := range sessions {
		log.Entries = append(log.Entries, sessionToEntry(sess))
	}
	return log
}

func LogToSessions(log Log) []proxy.Session {
	out := make([]proxy.Session, 0, len(log.Entries))
	for _, e := range log.Entries {
		if e.Request.URL == "" && e.Request.Method == "" {
			continue
		}
		out = append(out, entryToSession(e))
	}
	return out
}

func sessionToEntry(sess proxy.Session) Entry {
	started := sess.StartedAt
	if started == "" {
		started = "1970-01-01T00:00:00Z"
	}
	dur := elapsedMS(sess.StartedAt, sess.FinishedAt)
	reqBody := bodyBytes(sess.Request.Body)
	e := Entry{
		StartedDateTime: started,
		Time:            dur,
		Request: Request{
			Method:      sess.Request.Method,
			URL:         sess.Request.URL,
			HTTPVersion: defaultHTTP(sess.Request.HTTPVersion),
			Cookies:     []NameValue{},
			Headers:     mapToHeaders(sess.Request.Headers),
			QueryString: queryFromURL(sess.Request.URL),
			HeadersSize: -1,
			BodySize:    len(reqBody),
		},
		Response: emptyResponse(),
		Timings: Timings{
			Blocked: -1,
			DNS:     -1,
			Connect: -1,
			Send:    0,
			Wait:    dur,
			Receive: 0,
			SSL:     -1,
		},
		SessionID:    sess.ID,
		ClientAddr:   sess.ClientAddr,
		Tags:         sess.Tags,
		ReplayedFrom: sess.ReplayedFrom,
	}
	if sess.Notes != nil {
		e.Notes = *sess.Notes
	}
	if len(reqBody) > 0 {
		e.Request.PostData = bodyToPostData(sess.Request.Body, headerValue(sess.Request.Headers, "Content-Type"))
	}
	if sess.Response != nil {
		respBody := bodyBytes(sess.Response.Body)
		ctype := headerValue(sess.Response.Headers, "Content-Type")
		e.Response = Response{
			Status:      sess.Response.StatusCode,
			StatusText:  http.StatusText(sess.Response.StatusCode),
			HTTPVersion: defaultHTTP(sess.Response.HTTPVersion),
			Cookies:     []NameValue{},
			Headers:     mapToHeaders(sess.Response.Headers),
			Content:     bodyToContent(sess.Response.Body, ctype),
			RedirectURL: headerValue(sess.Response.Headers, "Location"),
			HeadersSize: -1,
			BodySize:    len(respBody),
		}
	}
	return e
}

func entryToSession(e Entry) proxy.Session {
	id := e.SessionID
	if id == "" {
		id = newID()
	}
	sess := proxy.Session{
		ID:           id,
		StartedAt:    e.StartedDateTime,
		ClientAddr:   e.ClientAddr,
		Tags:         e.Tags,
		ReplayedFrom: e.ReplayedFrom,
		Request: proxy.HTTPMsg{
			Method:      e.Request.Method,
			URL:         e.Request.URL,
			HTTPVersion: e.Request.HTTPVersion,
			Headers:     headersToMap(e.Request.Headers),
			Body:        postDataToBody(e.Request.PostData),
		},
	}
	if e.Notes != "" {
		n := e.Notes
		sess.Notes = &n
	}
	if e.Time > 0 {
		if t, err := time.Parse(time.RFC3339Nano, e.StartedDateTime); err == nil {
			sess.FinishedAt = t.Add(time.Duration(e.Time * float64(time.Millisecond))).UTC().Format(time.RFC3339Nano)
		}
	}
	if isEmptyHARResponse(e.Response) {
		return sess
	}
	sess.Response = &proxy.HTTPMsg{
		StatusCode:  e.Response.Status,
		HTTPVersion: e.Response.HTTPVersion,
		Headers:     headersToMap(e.Response.Headers),
		Body:        contentToBody(e.Response.Content),
	}
	return sess
}

func emptyResponse() Response {
	return Response{
		Status:      0,
		StatusText:  "",
		HTTPVersion: "HTTP/1.1",
		Cookies:     []NameValue{},
		Headers:     []NameValue{},
		Content:     Content{Size: 0, MimeType: ""},
		RedirectURL: "",
		HeadersSize: -1,
		BodySize:    0,
	}
}

func isEmptyHARResponse(r Response) bool {
	if r.Status != 0 {
		return false
	}
	if r.Content.Text != "" || r.Content.Size > 0 {
		return false
	}
	if len(r.Headers) > 0 {
		return false
	}
	return true
}

func defaultHTTP(v string) string {
	if v == "" {
		return "HTTP/1.1"
	}
	return v
}

func mapToHeaders(m map[string]string) []NameValue {
	out := []NameValue{}
	for k, v := range m {
		out = append(out, NameValue{Name: k, Value: v})
	}
	return out
}

func headersToMap(hs []NameValue) map[string]string {
	out := map[string]string{}
	for _, h := range hs {
		if h.Name == "" {
			continue
		}
		if prev, ok := out[h.Name]; ok {
			out[h.Name] = prev + ", " + h.Value
			continue
		}
		out[h.Name] = h.Value
	}
	return out
}

func headerValue(m map[string]string, name string) string {
	for k, v := range m {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func queryFromURL(raw string) []NameValue {
	out := []NameValue{}
	u, err := url.Parse(raw)
	if err != nil {
		return out
	}
	for k, vs := range u.Query() {
		for _, v := range vs {
			out = append(out, NameValue{Name: k, Value: v})
		}
	}
	return out
}

func bodyBytes(b proxy.Body) []byte {
	if strings.EqualFold(b.Encoding, "base64") {
		raw, err := base64.StdEncoding.DecodeString(b.Content)
		if err != nil {
			return []byte(b.Content)
		}
		return raw
	}
	return []byte(b.Content)
}

func bodyToPostData(b proxy.Body, mime string) *PostData {
	pd := &PostData{MimeType: mime, Text: b.Content}
	if strings.EqualFold(b.Encoding, "base64") {
		pd.Encoding = "base64"
	}
	return pd
}

func bodyToContent(b proxy.Body, mime string) Content {
	c := Content{Size: len(bodyBytes(b)), MimeType: mime, Text: b.Content}
	if strings.EqualFold(b.Encoding, "base64") {
		c.Encoding = "base64"
	}
	return c
}

func postDataToBody(pd *PostData) proxy.Body {
	if pd == nil {
		return proxy.Body{Encoding: "utf8", Content: ""}
	}
	text := pd.Text
	if text == "" && len(pd.Params) > 0 {
		text = paramsToForm(pd.Params)
	}
	enc := "utf8"
	if strings.EqualFold(pd.Encoding, "base64") {
		enc = "base64"
	}
	return proxy.Body{Encoding: enc, Content: text}
}

func paramsToForm(params []Param) string {
	var parts []string
	for _, p := range params {
		if p.FileName != "" {
			continue
		}
		parts = append(parts, url.QueryEscape(p.Name)+"="+url.QueryEscape(p.Value))
	}
	return strings.Join(parts, "&")
}

func contentToBody(c Content) proxy.Body {
	enc := "utf8"
	if strings.EqualFold(c.Encoding, "base64") {
		enc = "base64"
	}
	return proxy.Body{Encoding: enc, Content: c.Text}
}

func elapsedMS(start, finish string) float64 {
	if start == "" || finish == "" {
		return 0
	}
	a, err1 := time.Parse(time.RFC3339Nano, start)
	b, err2 := time.Parse(time.RFC3339Nano, finish)
	if err1 != nil || err2 != nil {
		return 0
	}
	ms := b.Sub(a).Seconds() * 1000
	if ms < 0 {
		return 0
	}
	return ms
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
