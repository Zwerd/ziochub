# ZIoCHub → Apigee: URL routing spec (Data Table IOC sync)

**Base URL (admin):** `google_secops_gateway_base_url`  
Example: `https://my-apigee.internal/secops-proxy` (trailing `/` is stripped; no `//v1beta`)

**Path variables (from ZIoCHub settings):**

- `{number}` = GCP project number  
- `{loc}` = location/region  
- `{inst}` = instance ID if set, else customer ID (UUID)  
- `{table_id}` = data table resource id  
- `{row_id}` = from LIST response field `name` (last segment)

**Builder:** `base.rstrip('/') + '/' + join(segments)` → always `{base}/v1beta/...`

---

## Routes to allow (production IOC lifecycle)

| Op | Method | Path (after gateway host) | Query |
|----|--------|---------------------------|--------|
| **CREATE** | `POST` | `/v1beta/projects/{number}/locations/{loc}/instances/{inst}/dataTables/{table_id}/dataTableRows:bulkCreate` | — |
| **LIST** | `GET` | `/v1beta/projects/{number}/locations/{loc}/instances/{inst}/dataTables/{table_id}/dataTableRows` | `pageSize=1000`, `filter={ioc_value}`, optional `pageToken` |
| **DELETE** | `DELETE` | `/v1beta/projects/{number}/locations/{loc}/instances/{inst}/dataTables/{table_id}/dataTableRows/{row_id}` | — |

**Note:** `dataTableRows:bulkCreate` is one path segment (colon included).

**LIST pagination:** ZIoCHub loops on `nextPageToken` until exhausted.

**Optional (admin test only):**  
`GET /v1beta/projects/.../dataTables/{table_id}` (no `dataTableRows`)

---

## Do not put in the base URL

- `/v1beta` (ZIoCHub adds it)
- Full `projects/...` path (ZIoCHub appends that)

**Correct base:** `https://my-apigee.internal/secops-proxy`  
**Incorrect base:** `https://my-apigee.internal/secops-proxy/v1beta`

---

## Auth (separate from paths above)

- **API key:** configured header (default `x-api-key`) + optional custom headers  
- **OAuth2:** token from `google_secops_gateway_oauth_token_url` (not necessarily under `{base}`), then `Authorization: Bearer` on Data Table calls
