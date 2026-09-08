# Finding: Server Version & Internal Node ID Disclosure via Lightstreamer Push Server

**Program:** eToro (etoro-mbb-og)  
**Severity:** Low  
**CWE:** CWE-200 (Exposure of Sensitive Information to Unauthorized Actor)  
**Affected Asset:** `push-lightstreamer.cloud.etoro.com`

---

## Summary

The eToro Lightstreamer real-time push server exposes its exact software version in every HTTP response header and leaks an internal node identifier in the root path response body. Both are accessible unauthenticated.

---

## Steps to Reproduce

**1. Version disclosure via Server header (any request):**
```
curl -si https://push-lightstreamer.cloud.etoro.com/ | grep -i server
```
Response:
```
server: Lightstreamer-Server/7.4.0 build 2326 (Lightstreamer Server - www.lightstreamer.com) ENTERPRISE edition
```

**2. Internal node ID disclosure via root path:**
```
curl -s https://push-lightstreamer.cloud.etoro.com/
```
Response body:
```
prod-ls-r-we-08
```

---

## Impact

- **Version information** allows an attacker to identify whether the server is running a version with known CVEs before attempting exploitation.
- **Node ID** (`prod-ls-r-we-08`) reveals internal infrastructure naming convention (prod/region/role/number), useful for reconnaissance of the server fleet topology.
- Both are accessible without any authentication or credentials.

---

## Remediation

1. Configure Lightstreamer to suppress or strip the `Server` response header (or replace with a generic value).
2. Remove the node ID response from the default `/` path, or restrict it to internal network access only.

---

## Evidence

```
$ curl -si https://push-lightstreamer.cloud.etoro.com/ | head -10
HTTP/2 200 
server: Lightstreamer-Server/7.4.0 build 2326 (Lightstreamer Server - www.lightstreamer.com) ENTERPRISE edition
content-type: text/html
content-length: 16

prod-ls-r-we-08
```
