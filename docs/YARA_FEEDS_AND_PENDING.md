# YARA public feeds vs. pending approval

This document describes how **approved** and **pending** YARA rules relate to **public feed endpoints** and **downstream integrations**. It is the operational contract for teams that poll `/feed/yara-*` or sync filenames from ZIoCHub.

## What the feeds expose

| Endpoint | Source on disk | What consumers see |
|----------|----------------|-------------------|
| `GET /feed/yara-list` | `DATA_YARA` (approved repository only) | One filename per line (`.yar` basenames). |
| `GET /feed/yara-content/<filename>` | Same directory | Raw UTF-8 rule text, or **404** if the file is not present under `DATA_YARA`. |

Rules that are **not** yet approved live under **`DATA_YARA_PENDING`** (`data/YARA_pending/` by default). **Pending rules are not listed and not served** by these endpoints.

## Effect of edits and approval workflow

1. **New upload** → file is written to pending; status `pending` until an admin approves.
2. **Admin approves** → file moves from pending to `DATA_YARA`; it appears on `/feed/yara-list` and is fetchable via `/feed/yara-content/...`.
3. **Content edit** on an **approved** rule → the updated body is stored under pending again and the file is **removed** from `DATA_YARA` until re-approval. Until then:
   - The name **disappears** from `yara-list`.
   - `yara-content` for that basename returns **404**.

This is intentional: **integrations only receive rules that have passed admin review**; draft or re-edited content is not published to the feed.

## TAXII / STIX

The TAXII 2.1 / STIX 2.1 collections expose **IOC** indicators, not YARA rule files. Behaviour of `/taxii2/...` is unrelated to `/feed/yara-*`.

## Guidance for integration owners

- Treat **temporary absence** of a previously seen filename from `yara-list` as **expected** while the rule is pending (e.g. after an edit), not necessarily as a sync bug.
- If a client caches `yara-content` by filename, **404** after a previously successful fetch usually means the rule was withdrawn from the approved set pending re-approval.
- For operational stability: approve pending YARA changes promptly after review, or coordinate maintenance windows if downstream systems alert on removals.

## Related code

- Feed handlers: `routes/feeds.py` (`feed_yara_list`, `feed_yara_content`).
- Approval and file moves: `routes/yara.py` (`approve_yara`, `update_yara`, `reject_yara`).
