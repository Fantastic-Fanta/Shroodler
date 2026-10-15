from __future__ import annotations

from shroodler.extractors.cloud_storage import extract_cloud_buckets


def _buckets(text: str) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for f in extract_cloud_buckets(text, "http://app/"):
        assert f.id == "cloud-storage-bucket"
        assert f.severity == "info"
        assert f.confidence == "heuristic"
        provider, bucket = "", ""
        for tok in f.evidence.split():
            if tok.startswith("provider="):
                provider = tok.split("=", 1)[1]
            if tok.startswith("bucket="):
                bucket = tok.split("=", 1)[1]
        out.add((provider, bucket))
    return out


def test_aws_s3_virtual_hosted_and_regional():
    got = _buckets(
        '<img src="https://my-assets.s3.amazonaws.com/logo.png">'
        '<link href="https://reports.s3.eu-west-1.amazonaws.com/a.css">'
    )
    assert ("aws-s3", "my-assets") in got
    assert ("aws-s3", "reports") in got


def test_aws_s3_path_style():
    got = _buckets("fetch('https://s3.amazonaws.com/legacy-bucket/data.json')")
    assert ("aws-s3", "legacy-bucket") in got


def test_gcs_vhost_and_path():
    got = _buckets(
        "https://cdn-bucket.storage.googleapis.com/x "
        "https://storage.googleapis.com/public-data/y "
        "https://storage.cloud.google.com/private-data/z"
    )
    assert ("gcs", "cdn-bucket") in got
    assert ("gcs", "public-data") in got
    assert ("gcs", "private-data") in got


def test_azure_do_and_r2():
    got = _buckets(
        "https://myaccount.blob.core.windows.net/container/file "
        "https://space1.nyc3.digitaloceanspaces.com/a "
        "https://acct123.r2.cloudflarestorage.com/b"
    )
    assert ("azure-blob", "myaccount") in got
    assert ("do-spaces", "space1") in got
    assert ("cloudflare-r2", "acct123") in got


def test_dedupes_repeated_bucket():
    findings = extract_cloud_buckets(
        "assets.s3.amazonaws.com assets.s3.amazonaws.com assets.s3.amazonaws.com",
        "http://app/",
    )
    assert len([f for f in findings if "bucket=assets" in f.evidence]) == 1


def test_no_buckets_and_empty():
    assert extract_cloud_buckets("", "http://app/") == []
    assert extract_cloud_buckets("just some html with no storage refs", "http://app/") == []
