from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["confirmed", "probable", "heuristic"]
Category = Literal[
    "header",
    "cookie",
    "secret",
    "exposed-file",
    "js-endpoint",
    "verbose-error",
    "autocomplete",
    "payload",
    "scan-note",
    "auth",
    "waf-challenge",
    "subresource",
    "tls",
    "smart-contract",
    "sast",
]
Mode = Literal["static", "headless", "ingest"]
StoppedReason = Literal["complete", "max-pages", "max-time"]
EdgeKind = Literal["html", "redirect", "form"]


class CrawlerInfo(BaseModel):
    name: str
    version: str
    mode: Mode


class FormField(BaseModel):
    name: str
    type: str
    hidden: bool
    disabled: bool | None = None
    readonly: bool | None = None


class Form(BaseModel):
    action: str
    method: str
    fields: list[FormField]
    enctype: str | None = None


class Cookie(BaseModel):
    name: str
    secure: bool
    http_only: bool
    same_site: Literal["Strict", "Lax", "None"] | None


class HeaderAnalysis(BaseModel):
    present: list[str]
    missing: list[str]


class Page(BaseModel):
    url: str
    status_code: int
    forms: list[Form] = Field(default_factory=list)
    params: list[str] = Field(default_factory=list)
    cookies: list[Cookie] = Field(default_factory=list)
    headers: HeaderAnalysis = Field(
        default_factory=lambda: HeaderAnalysis(present=[], missing=[])
    )
    js_files: list[str] = Field(default_factory=list)


class ProofQuote(BaseModel):
    """A verbatim excerpt of captured traffic that demonstrates a finding.

    ``text`` must appear character-for-character inside the proof's bound
    request or response excerpt (whichever ``source`` names). This is the
    unit that makes a finding falsifiable from its own record: a reviewer can
    locate the quote in the retained traffic rather than trust a prose claim.
    """

    source: Literal["request", "response"]
    text: str = Field(min_length=1)


class Proof(BaseModel):
    """Binds a finding to the single HTTP exchange that demonstrates it.

    A finding may be marked ``verified`` only when it carries a well-formed
    proof: the request that was sent, the response that came back (as bounded
    verbatim excerpts), and at least one quote drawn from that traffic. When a
    proxy session captured the exchange, ``session_id`` points at it so the
    full, unbounded record can be retrieved from the proxy store.

    This is Shroodler's own evidence-binding model under Apache-2.0, a
    clean-room reimplementation of the architecture (not the code) behind
    ARTEX's AGPL evidence binding.
    """

    method: str
    url: str = Field(min_length=1)
    status_code: int | None = Field(default=None, ge=0, le=599)
    session_id: str | None = None
    request_excerpt: str | None = None
    response_excerpt: str | None = None
    quotes: list[ProofQuote] = Field(default_factory=list)
    captured_at: str | None = None

    @model_validator(mode="after")
    def _quotes_are_verbatim(self) -> Proof:
        for q in self.quotes:
            hay = (
                self.request_excerpt
                if q.source == "request"
                else self.response_excerpt
            )
            if hay is None or q.text not in hay:
                raise ValueError(
                    f"proof quote not found verbatim in the bound "
                    f"{q.source} excerpt: {q.text!r}"
                )
        return self


class Finding(BaseModel):
    id: str
    severity: Severity
    category: Category
    url: str
    description: str
    evidence: str | None = None
    confidence: Confidence | None = None
    proof: Proof | None = None
    verified: bool = False

    @model_validator(mode="after")
    def _verified_requires_proof(self) -> Finding:
        if self.verified:
            if self.proof is None:
                raise ValueError(
                    "verified finding must carry a proof binding it to the "
                    "request/response that demonstrates it"
                )
            if not self.proof.quotes:
                raise ValueError(
                    "verified finding's proof must carry at least one verbatim "
                    "quote from the bound traffic"
                )
        return self


class JsEndpoint(BaseModel):
    source: str
    endpoint: str


class CrawlEdge(BaseModel):
    """A link the crawl followed: an HTML link, a redirect, or a form action."""

    from_url: str
    to_url: str
    kind: EdgeKind


class CapturedEndpoint(BaseModel):
    """XHR/fetch (or form POST) intercepted during a headless crawl."""

    url: str
    method: str = "GET"
    params: list[dict] = Field(default_factory=list)


class CrawlStats(BaseModel):
    pages_crawled: int = 0
    pages_challenged: int = 0
    requests: int = 0
    elapsed_ms: int = 0
    stopped_reason: StoppedReason = "complete"


class CrawlResult(BaseModel):
    target: str
    scan_started_at: str
    scan_finished_at: str
    crawler: CrawlerInfo
    pages: list[Page]
    findings: list[Finding]
    edges: list[CrawlEdge] = Field(default_factory=list)
    unfetched: list[str] = Field(default_factory=list)
    js_endpoints: list[JsEndpoint] = Field(default_factory=list)
    xhr_endpoints: list[CapturedEndpoint] = Field(default_factory=list)
    stats: CrawlStats | None = None

    def to_dict(self) -> dict:
        data = self.model_dump(mode="json")
        if data.get("stats") is None:
            data.pop("stats", None)
        if not data.get("unfetched"):
            data.pop("unfetched", None)
        from shroodler.confidence import stamp_findings

        stamp_findings(data.get("findings") or [])
        return data
