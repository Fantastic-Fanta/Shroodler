# Finding: Verbose Error Messages Disclose Internal .NET Class Names and Trace IDs

**Severity:** Informational / Low  
**CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)  
**Asset:** www.etoro.com  
**Endpoint:** `POST /api/abtesting/variations`

## Summary

When an invalid request body is sent to the A/B testing batch endpoint, the server returns a 400 response that discloses:
- Internal .NET namespace and class name: `eToro.ABTestingProxy.Domain.Models.GetBatchVariationRequest`
- OpenTelemetry distributed trace ID
- Internal service name (`ABTestingProxy`)

## Steps to Reproduce

```
POST /api/abtesting/variations?client_request_id=<uuid>
Authorization: <Bearer JWE>
accounttype: Real
applicationidentifier: ReToro
Content-Type: application/json

["experiment_name_1", "experiment_name_2"]
```

## Response (400)

```json
{
  "errors": {
    "[0]": [
      "Error converting value \"experiment_name_1\" to type 'eToro.ABTestingProxy.Domain.Models.GetBatchVariationRequest'. Path '[0]', line 1, position 21."
    ]
  },
  "type": "https://tools.ietf.org/html/rfc9110#section-15.5.1",
  "title": "One or more validation errors occurred.",
  "status": 400,
  "traceId": "00-32e85d0081ffedaad5678eb9eaf058e5-c7df429577aab86c-00"
}
```

## Impact

- Internal service architecture partially revealed (`ABTestingProxy` microservice)
- .NET assembly namespace aids in understanding server-side architecture
- OpenTelemetry trace IDs in error responses allow request correlation in eToro's internal distributed tracing infrastructure (if accessible)

## Remediation

Return generic validation error messages without internal type names. Use a custom error handler to strip `type` path details and suppress internal class names. Remove `traceId` from public-facing error responses, or restrict it to internal/authenticated contexts.

## Notes

Requires a valid authenticated session. The normal correct request body format is an array of objects, not strings. This is triggered by sending strings instead of the expected `GetBatchVariationRequest` object structure.
