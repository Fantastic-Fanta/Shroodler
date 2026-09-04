from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
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
]
Mode = Literal["static", "headless", "ingest"]
StoppedReason = Literal["complete", "max-pages", "max-time"]


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


class Finding(BaseModel):
    id: str
    severity: Severity
    category: Category
    url: str
    description: str
    evidence: str | None = None


class JsEndpoint(BaseModel):
    source: str
    endpoint: str


class CrawlStats(BaseModel):
    pages_crawled: int = 0
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
    js_endpoints: list[JsEndpoint] = Field(default_factory=list)
    stats: CrawlStats | None = None

    def to_dict(self) -> dict:
        data = self.model_dump(mode="json")
        if data.get("stats") is None:
            data.pop("stats", None)
        return data
