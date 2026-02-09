# Untranslated Elements Report
## Missing `data-i18n` or `data-i18n-placeholder` Attributes

---

## tab-live-stats (Live Stats) - Lines 113-216

| Line | Element Type | English Text | Context |
|------|--------------|--------------|---------|
| 118 | `<span>` | Live Updating... | Live indicator status text |
| 192 | `<span>` | Top Email Domains | Chart heading |
| 200 | `<span>` | Campaign Impact | Chart heading |
| 208 | `<span>` | Live Feed | Chart heading |

---

## tab-search (Search & Investigate) - Lines 219-275

| Line | Element Type | English Text | Context |
|------|--------------|--------------|---------|
| 237 | `<a>` | Export All CSV | Export button link text |
| 244 | `<button>` | Prev | Pagination button |
| 246 | `<button>` | Next | Pagination button |
| 248-250 | `<option>` | 25, 50, 100 | Page size options (numeric values, may be acceptable) |
| 262 | `<th>` | Ticket ID | Table header |
| 264 | `<th>` | Campaign | Table header |

---

## tab-bulk-unified (Bulk Upload - TXT/CSV) - Lines 277-415

| Line | Element Type | English Text | Context |
|------|--------------|--------------|---------|
| 281 | `<h2>` | Bulk Intelligence Upload | Main heading |
| 283 | `<button>` | TXT | Mode toggle button |
| 284 | `<button>` | CSV | Mode toggle button |
| 289 | `<h4>` | 📝 TXT Format & Parsing Logic | Info card heading |
| 290 | `<p>` | Upload raw log files or IOC lists. Parser detects IOCs automatically. Format: `IOC_VALUE # Metadata`. Extracts Ticket ID, Analyst, Timestamps. | Info card description |
| 300 | `placeholder` | analyst | TXT username input placeholder |
| 304 | `placeholder` | ID | TXT ticket ID input placeholder |
| 309-313 | `<option>` | Permanent, 1 Week, 1 Month, 3 Months, 1 Year | TTL options (some may already be translated elsewhere) |
| 317 | `<label>` | Campaign | Campaign select label |
| 319 | `<option>` | — None — | Campaign select default option |
| 323 | `<label>` | Default Comment | Default comment label |
| 324 | `placeholder` | If line has no comment | Default comment input placeholder |
| 326 | `<button>` | Preview | Preview button |
| 337 | `placeholder` | analyst | CSV username input placeholder |
| 342-346 | `<option>` | Permanent, 1 Week, 1 Month, 3 Months, 1 Year | TTL options |
| 350 | `<label>` | Ticket | CSV ticket label |
| 351 | `placeholder` | ID | CSV ticket ID input placeholder |
| 354 | `<label>` | Campaign | CSV campaign label |
| 356 | `<option>` | — None — | CSV campaign select default option |
| 370 | `<button>` | Approve All Valid | TXT staging approve button |
| 371 | `<span>` | Found 0 items | TXT staging count text (dynamic number, but "Found" and "items" need translation) |
| 377-384 | `<th>` | IOC, Type, Ticket, Analyst, Date, Comment, Expiration, Actions | TXT staging table headers (8 columns) |
| 393 | `<button>` | Approve All Valid | CSV staging approve button |
| 394 | `<span>` | Found 0 items | CSV staging count text (dynamic number, but "Found" and "items" need translation) |
| 400-407 | `<th>` | IOC, Type, Ticket, Analyst, Date, Comment, Expiration, Actions | CSV staging table headers (8 columns) |

---

## tab-yara (YARA Manager) - Lines 418-476

| Line | Element Type | English Text | Context |
|------|--------------|--------------|---------|
| 428 | `placeholder` | TICKET-12345 | YARA ticket ID placeholder |
| 436 | `<label>` | Campaign (optional) | Campaign select label |
| 438 | `<option>` | — None — | Campaign select default option |
| 452 | `<button>` | Submit YARA Rule | Submit button |
| 454 | `<h3>` | Active Rules Repository | Section heading |
| 455 | `placeholder` | 🔍 Filter rules by name, comment, analyst, or ticket... | Filter input placeholder |
| 460-466 | `<th>` | Rule Name, Comment, Size, Date, Analyst, Ticket, Actions | YARA rules table headers (7 columns) |
| 471 | `<td>` | Loading... | Loading state text |

---

## tab-submit (Single IOC Submission) - Lines 479-543

| Line | Element Type | English Text | Context |
|------|--------------|--------------|---------|
| 494-498 | `<option>` | IP Address, Domain, Hash (MD5/SHA1/SHA256), Email, URL | IOC type options |
| 513 | `placeholder` | analyst_name | Username input placeholder |
| 519 | `placeholder` | TICKET-12345 | Ticket ID input placeholder |
| 533 | `<label>` | Campaign (optional) | Campaign select label |
| 535 | `<option>` | — None — | Campaign select default option |

---

## tab-champs (Champs Analysis) - Lines 546-586

| Line | Element Type | English Text | Context |
|------|--------------|--------------|---------|
| 566 | `<h3>` | Analysts Leaderboard | Section heading |

---

## tab-campaigns (Campaign Graph) - Lines 589-642

| Line | Element Type | English Text | Context |
|------|--------------|--------------|---------|
| 590 | `<h2>` | Campaign Graph | Main heading |
| 596 | `<h3>` | Active Campaigns | Sidebar heading |
| 597 | `<button>` | Export CSV | Export button (title attribute) |
| 600 | `<li>` | Loading… | Loading state text |
| 611 | `<h3>` | Create Campaign | Sidebar heading |
| 614 | `<label>` | Name | Campaign name label |
| 615 | `placeholder` | Campaign name | Campaign name input placeholder |
| 618 | `<label>` | Description | Campaign description label |
| 619 | `placeholder` | Optional description | Campaign description textarea placeholder |
| 621 | `<button>` | Create Campaign | Create button |
| 625 | `<h3>` | Link IOC | Sidebar heading |
| 628 | `<label>` | IOC Value | Link IOC value label |
| 629 | `placeholder` | Exact IOC value | Link IOC value input placeholder |
| 632 | `<label>` | Campaign | Link IOC campaign label |
| 634 | `<option>` | -- Select campaign -- | Campaign select default option |
| 637 | `<button>` | Link IOC | Link button |

---

## editModal - Lines 649-693

| Line | Element Type | English Text | Context |
|------|--------------|--------------|---------|
| 674 | `<label>` | Ticket ID | Ticket ID label |
| 675 | `placeholder` | e.g. INC-12345 | Ticket ID input placeholder |
| 678 | `<label>` | Campaign Assignment | Campaign assignment label |
| 680 | `<option>` | None / Unassigned | Campaign select default option |

---

## yaraPreviewModal - Lines 696-704

| Line | Element Type | English Text | Context |
|------|--------------|--------------|---------|
| 699 | `<h3>` | File Preview | Modal heading |
| 700 | `<button>` | Close | Close button |

---

## yaraEditModal - Lines 707-718

| Line | Element Type | English Text | Context |
|------|--------------|--------------|---------|
| 710 | `<h3>` | Edit Rule | Modal heading |
| 712 | `<button>` | Cancel | Cancel button |
| 713 | `<button>` | Save | Save button |
| 716 | `placeholder` | YARA rule content... | Textarea placeholder |

---

## campaignEditModal - Lines 721-740

| Line | Element Type | English Text | Context |
|------|--------------|--------------|---------|
| 723 | `<h3>` | Edit Campaign | Modal heading |
| 727 | `<label>` | Campaign Name | Campaign name label |
| 728 | `placeholder` | Campaign name | Campaign name input placeholder |
| 731 | `<label>` | Description | Description label |
| 732 | `placeholder` | Optional description | Description textarea placeholder |
| 735 | `<button>` | Cancel | Cancel button |
| 736 | `<button>` | Save Changes | Save button |

---

## yaraMetaEditModal - Lines 743-772

| Line | Element Type | English Text | Context |
|------|--------------|--------------|---------|
| 745 | `<h3>` | Edit YARA Metadata | Modal heading |
| 749 | `<label>` | Filename | Filename label |
| 753 | `<label>` | Ticket ID | Ticket ID label |
| 754 | `placeholder` | e.g. TICKET-12345 | Ticket ID input placeholder |
| 757 | `<label>` | Comment | Comment label |
| 758 | `placeholder` | Notes about this rule | Comment textarea placeholder |
| 761 | `<label>` | Campaign Assignment | Campaign assignment label |
| 763 | `<option>` | -- None -- | Campaign select default option |
| 767 | `<button>` | Cancel | Cancel button |
| 768 | `<button>` | Save Changes | Save button |

---

## Summary by Section

- **tab-live-stats**: 4 untranslated elements
- **tab-search**: 6 untranslated elements
- **tab-bulk-unified**: 30+ untranslated elements (largest section)
- **tab-yara**: 9 untranslated elements
- **tab-submit**: 5 untranslated elements
- **tab-champs**: 1 untranslated element
- **tab-campaigns**: 17 untranslated elements
- **editModal**: 4 untranslated elements
- **yaraPreviewModal**: 2 untranslated elements
- **yaraEditModal**: 4 untranslated elements
- **campaignEditModal**: 7 untranslated elements
- **yaraMetaEditModal**: 9 untranslated elements

**Total: ~100+ untranslated elements**
