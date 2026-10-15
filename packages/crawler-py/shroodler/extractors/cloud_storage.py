"""Cloud object-storage bucket references mined from HTML/JS.

Attack-surface recon, not a vulnerability by itself: an app's pages and bundles
often name the S3/GCS/Azure/R2/Spaces buckets they pull assets from, and a
misconfigured one (public list/read, or writable) is a common finding. This
extractor records the buckets a crawl saw so a tester (or a follow-up active
check) knows where to look. One informational finding per unique bucket,
deduped, like the js-endpoint surface findings.
"""

from __future__ import annotations

import re

from shroodler.models import Finding

# (provider, compiled regex, group index holding the bucket/account name).
# Bucket-name-ish labels (dot/dash allowed, length-bounded).
_S3 = r"[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]"
_GCS = r"[a-z0-9][a-z0-9._\-]{1,61}"
_REGION = r"(?:[.-][a-z0-9\-]+)?"

_PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    # AWS S3 virtual-hosted: bucket.s3.amazonaws.com / bucket.s3.<region>.amazonaws.com
    ("aws-s3", re.compile(rf"\b({_S3})\.s3{_REGION}\.amazonaws\.com\b", re.I), 1),
    # AWS S3 path-style: s3.amazonaws.com/bucket / s3-<region>.amazonaws.com/bucket
    ("aws-s3", re.compile(rf"\bs3{_REGION}\.amazonaws\.com/({_S3})", re.I), 1),
    # Google Cloud Storage virtual-hosted and path-style.
    ("gcs", re.compile(rf"\b({_GCS})\.storage\.googleapis\.com\b", re.I), 1),
    ("gcs", re.compile(rf"\bstorage\.(?:googleapis|cloud\.google)\.com/({_GCS})", re.I), 1),
    # Azure Blob Storage: account.blob.core.windows.net
    ("azure-blob", re.compile(r"\b([a-z0-9]{3,24})\.blob\.core\.windows\.net\b", re.I), 1),
    # DigitalOcean Spaces: bucket.<region>.digitaloceanspaces.com
    ("do-spaces", re.compile(rf"\b({_S3})\.[a-z0-9\-]+\.digitaloceanspaces\.com\b", re.I), 1),
    # Cloudflare R2: account.r2.cloudflarestorage.com
    ("cloudflare-r2", re.compile(r"\b([a-z0-9]{2,64})\.r2\.cloudflarestorage\.com\b", re.I), 1),
]

# Never flag the provider's own bare service host as a "bucket".
_SERVICE_HOSTS = frozenset({"s3", "storage", "www", "blob"})


def extract_cloud_buckets(text: str, url: str) -> list[Finding]:
    """One info finding per unique (provider, bucket) referenced in the text."""
    if not text:
        return []
    seen: set[tuple[str, str]] = set()
    findings: list[Finding] = []
    for provider, pattern, group in _PATTERNS:
        for match in pattern.finditer(text):
            bucket = match.group(group).rstrip(".").lower()
            if not bucket or bucket in _SERVICE_HOSTS:
                continue
            key = (provider, bucket)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    id="cloud-storage-bucket",
                    severity="info",  # type: ignore[arg-type]
                    category="exposed-file",
                    url=url,
                    description=(
                        f"Referenced a {provider} object-storage bucket "
                        f"{bucket!r}. Informational attack surface: check whether "
                        "the bucket allows public list/read or anonymous writes."
                    ),
                    evidence=f"provider={provider} bucket={bucket}",
                    confidence="heuristic",  # type: ignore[arg-type]
                )
            )
    return findings
