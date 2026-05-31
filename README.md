# FinTrak

FinTrak is a Flask + Firestore finance tracker for personal spending, balances, recurring rules, split bills, trips, analytics, admin settings, and view-only access.

The app is server-rendered with Jinja templates, Bootstrap 5, custom CSS, vanilla JavaScript, Chart.js, Firestore Admin SDK, a browser service worker, and a `localStorage` based offline queue.

## Main Features

| Area | What the code supports now |
|---|---|
| Transactions | Add, edit, delete, search, sort, and paginate transactions. Transaction page size is 6 rows. |
| Balance | Add delta entries, sync to an absolute balance, edit/delete displayed balance rows, and recalculate later rows. |
| Recurring | Expense recurring rules and balance recurring rules with create/edit/delete flows. |
| Splits | Split documents, live/saved status, split entries, per-person totals, and trip connection/disconnection flows. |
| Trips | Fixed-budget trips and split-spend trips, with create/edit/delete/disconnect flows. |
| Analytics | Spend analytics, balance analytics, Chart.js charts, summary cards, tables, and CSV export for transactions. |
| Management | Categories, split people, view-only password, account username/email, and account password management. |
| View-only mode | Read-only access with write controls hidden or blocked server-side. |

## Current Row Limits

Most list/cache preview limits are defined in `constants.py` and are currently 6 rows.

| Constant | Value | Used for |
|---|---:|---|
| `TRANSACTION_PAGE_SIZE` | 6 | Transactions page pagination |
| `RECENT_TRANSACTIONS_CACHE_LIMIT` | 6 | Browser snapshot recent transactions |
| `BALANCE_HISTORY_TABLE_LIMIT` | 6 | Balance history table and browser snapshot balance history |
| `RECURRING_RULE_TABLE_LIMIT` | 6 | Recurring expense and recurring balance previews |
| `SPLIT_DOCUMENT_TABLE_LIMIT` | 6 | Split document previews |
| `SPLIT_ENTRY_TABLE_LIMIT` | 6 | Live split entries in browser snapshot |
| `TRIP_TABLE_LIMIT` | 6 | Trip previews |

## Offline And Render Sleep Flow

FinTrak is built to keep the app usable when Render is slow, waking, or temporarily unreachable.

When Render is awake:

1. Flask loads pages normally.
2. Login checks the submitted username/password against Firestore.
3. After a successful login, the browser stores a hashed cached-login copy for that browser.
4. Authenticated page loads refresh `/api/cache_snapshot` in the background.
5. The service worker keeps the login shell and static assets available for later offline/asleep loads.

When Render is asleep or unreachable:

1. The browser can show the cached login page only if it was opened successfully before.
2. Offline login works only for the previously cached full user or view-only user in that browser.
3. The cached password value is a SHA-256 hash, not plain text.
4. Offline login queues an `offline_login` job and a `cache_refresh` job in `localStorage`.
5. Later writes are queued after that in the same queue.
6. When the service responds again, queued jobs run in order and the browser snapshot is refreshed again after sync.

There is no active Flask/server in-memory data cache documented here. Server routes read current data from Firestore, with environment fallbacks only where the code explicitly has them.

## Cached Data

| Cached thing | Stored where | Updated when | Expiry time | Amount |
|---|---|---|---|---|
| Login page UI | Browser service-worker cache `fintrak-shell-v1` | First successful online visit, then when the service worker asset cache is replaced | No fixed timer in code; until browser clears it or a new service-worker cache replaces it | Login/view login shell plus static CSS/JS/icons listed in `static/sw.js` |
| Offline login user | Browser `localStorage` key `fintrak_cached_auth` | After successful login, via temporary `fintrak_temp_auth` commit | No fixed expiry in code | 1 full/admin user and 1 view-only user |
| Pending jobs/actions | Browser `localStorage` key `fintrak_pending_actions` | When supported actions happen while offline/asleep or before background sync completes | Until synced, permanently rejected, or manually cleared | No fixed limit |
| App snapshot | Browser `localStorage` key `fintrak_cache_snapshot_v1` | `/api/cache_snapshot` refresh after authenticated loads, queue sync, and explicit refresh calls | 10 days | Full snapshot rows below |
| Recent transactions | Inside app snapshot | Snapshot refresh | 10 days | 6 rows |
| Balance history | Inside app snapshot | Snapshot refresh | 10 days | 6 rows, excluding transaction-generated balance rows |
| Recurring rules | Inside app snapshot | Snapshot refresh | 10 days | 6 rows |
| Recurring balance rules | Inside app snapshot | Snapshot refresh | 10 days | 6 rows |
| Splits list | Inside app snapshot | Snapshot refresh | 10 days | 6 rows |
| Trips list | Inside app snapshot | Snapshot refresh | 10 days | 6 rows |
| Live split entries | Inside app snapshot | Snapshot refresh | 10 days | 6 rows |
| Current balance | Inside app snapshot | Snapshot refresh | 10 days | 1 current balance |
| Live split totals | Inside app snapshot | Snapshot refresh | 10 days | All people totals for the live split summary |
| Categories | Inside app snapshot | Snapshot refresh | 10 days | All categories returned by `get_categories()` |
| Split people | Inside app snapshot | Snapshot refresh | 10 days | All people returned by `get_split_people()` |

## Background Queue

The offline/background queue is stored in browser `localStorage`, not IndexedDB.

Supported queued form/action types include transactions, split entries, split documents, live/unlive split actions, recurring rules, recurring balance rules, trips, category management, split-person management, offline login, cache refresh, and balance add/sync actions.

Queue behavior verified in code:

| Behavior | Code status |
|---|---|
| FIFO order | `static/js/offline_queue.js` always processes the first queued item. |
| Durable across reloads | Queue lives in `localStorage` under `fintrak_pending_actions`. |
| New jobs during sync | Sync re-reads `localStorage` each loop and removes only the exact completed job, so newly appended jobs are preserved. |
| Cross-tab sync collision reduction | A `fintrak_pending_actions_sync_lock` lock reduces simultaneous queue flushes across tabs. |
| Server awake check | Normal queued writes check `/api/render_status` before posting. |
| Snapshot refresh | Browser snapshot refresh is requested after queued jobs and again when the queue reaches zero. |
| Permanent 4xx failures | Permanent invalid jobs are removed so the queue does not stay blocked forever. |

Duplicate protection is partial, not universal:

| Write area | Duplicate protection status |
|---|---|
| Transaction create/edit/delete | Uses `client_action_id` or `client_actions` log. Strongest protection. |
| Split entry create/edit/delete | Uses `client_action_id` or `client_actions` log. Strongest protection. |
| Balance add/sync | Uses `client_action_id` through `client_actions`. |
| Split document create/edit/delete/live/unlive | Queued in order, but no full `client_action_id` dedupe in the active routes. |
| Recurring and recurring balance rules | Queued in order, but no full `client_action_id` dedupe in the active routes. |
| Trips | Queued in order, but no full `client_action_id` dedupe in the active routes. |
| Categories and split people | Queued in order, but no full `client_action_id` dedupe in the active routes. |

So the Render sleep concept is successful for loading the cached shell, offline login for the last cached user, preserving pending jobs, and syncing them in order. The remaining write redundancy risk is only for endpoints that do not yet have server-side idempotency if the server completes a write but the browser loses the response before removing the queued job.

## Balance Ledger Behavior

Balance rows use two related fields:

| Field | Meaning |
|---|---|
| `type` | The broad row source, such as `add`, `sync`, transaction edit/delete adjustment, or transaction-created balance movement. |
| `balance_mode` | The editable balance mode marker: `add` or `sync`. |

Current behavior:

| Action | Math |
|---|---|
| Add row | Stores a delta `x`. Balance changes by `+x`. |
| Delete add row | Removes that delta. Net effect is `-x` from following balances. |
| Edit add row from `x` to `z` | Following balances change by `z - x`. |
| Sync row | Stores an absolute balance `x`; its delta is `x - previous_balance`. |
| Delete sync row | Removes that sync anchor and recalculates following rows from the previous balance. |
| Edit sync row from absolute `x` to `z` | New delta becomes `z - previous_balance`; following rows are recalculated. |
| Convert add to sync | Edit modal sends `mode: sync`, stores the row as an absolute balance, and recalculates later rows. |
| Convert sync to add | Edit modal sends `mode: add`, stores the row as a delta, and recalculates later rows. |

During recalculation, later sync rows stay absolute anchors. This prevents editing an earlier add row from accidentally moving a later absolute sync balance.

All displayed balance rows are editable/deletable for full users. View-only users cannot write.

## Analytics Offline Behavior

Full analytics need the server because they call Firestore-backed API routes.

When offline/asleep:

| Page | Offline behavior |
|---|---|
| Spend analytics | If a usable app snapshot exists, it shows limited cached spend data from recent cached transactions and explains that full analytics require the server. If no snapshot exists, it shows an unavailable message. |
| Balance analytics | If a usable app snapshot exists, it shows limited cached balance history and explains that full analytics require the server. If no snapshot exists, it shows an unavailable message. |

Charts are destroyed/cleared for offline fallback data so the page does not pretend to show complete analytics.

## UI And Components

The app uses a shared base layout, shared CSS variables, Bootstrap classes, and Jinja macros in `templates/macros/ui.html`.

Reusable UI now covers:

| Component area | Current status |
|---|---|
| Page shell/navbar | Shared through `templates/base.html`. |
| Auth theme toggle | Shared macro. |
| Protected/view-only badges | Shared macro. |
| Compact badges | Shared macro and CSS variants. |
| People picker | Shared macro and CSS. |
| Choice panels | Shared macro and CSS. |
| Tables | Shared `.table-shell`, `.table`, responsive labels, and action classes. |
| Inputs/selects | Standard `.form-control` / `.form-select` styling. |
| Modals | Bootstrap modal structure with shared app styling. |

Recent verification found and fixed risky dark-mode modal text classes. Static template/JS checks did not find app-owned inline `style=` usage except external Google Fonts URL text containing `display=swap`.

## Date Display

Visible UI dates are formatted by the frontend in a compact style such as:

```text
12 may '26
```

Backend storage and Firestore timestamps were not changed by that display-format work.

## Security Notes

| Area | Current behavior |
|---|---|
| Flask secret | `FLASK_SECRET` is required for sessions/CSRF. |
| Admin/full password | Stored as a Werkzeug-compatible password hash in Firestore. |
| View-only password | Uses Firestore hash after it is set; can fall back to `VIEW_PASS` if no Firestore value exists. |
| Cached offline password | Stored in this browser as SHA-256 hash for offline comparison. |
| CSRF | Enabled for standard Flask forms and included in queued JSON requests where the frontend sends it. |
| View-only writes | Protected controls are hidden and write routes check full login where required. |
| Session cookies | HTTP-only, SameSite Lax, and Secure when `FORCE_HTTPS=true`. |

## Local Setup

Create and activate a virtual environment:

```bash
python -m venv venv
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Set required environment variables:

```bash
set FLASK_SECRET=replace-with-long-random-secret
set FIREBASE_CREDENTIALS={"type":"service_account",...}
set ADMIN_USER=admin@example.com
set VIEW_PASS=initial-view-only-password
```

Run locally:

```bash
set FLASK_APP=app.py
flask run
```

Open:

```text
http://127.0.0.1:5000
```

## Environment Variables

| Variable | Meaning |
|---|---|
| `FLASK_SECRET` | Required Flask session and CSRF signing secret. |
| `FIREBASE_CREDENTIALS` | Required Firebase service account JSON string. |
| `ADMIN_USER` | Comma-separated usernames allowed for admin password setup. |
| `VIEW_PASS` | Optional initial view-only password fallback. |
| `FORCE_HTTPS` | Set to `true` behind HTTPS so session cookies are secure. |
| `SESSION_LIFETIME_HOURS` | Login duration. Default is 12. |
| `OCCURRENCE_WINDOW_SECS` | Recurring duplicate-detection window. Default is 60. |
| `FIRESTORE_TIMEOUT_SECONDS` | Timeout for critical Firestore reads. Default is 8. |
| `ENABLE_DEBUG_ROUTES` | Optional diagnostics route switch. Keep unset or false in production. |
| `LOG_LEVEL` | Flask log level. Default is INFO. |
| `FLASK_DEBUG` | Local debug flag. Keep disabled in production. |

## Production Checklist

- Use a long random `FLASK_SECRET`.
- Store `FIREBASE_CREDENTIALS` securely in the hosting provider.
- Set `FORCE_HTTPS=true` when deployed behind HTTPS.
- Keep `FLASK_DEBUG` disabled in production.
- Restrict Firebase service account permissions to what the app needs.
- Create any Firestore indexes requested by range/order queries.
- Test full login, view-only login, cached login, queue retry, and background sync.
- Test transaction, balance, recurring, split, trip, management, analytics, dark mode, and mobile layouts.

## Verification Performed

Code-grounded checks used during the final README update:

```bash
rg -n "client_action_id|data-offline-queue|balance_mode|fintrak_pending_actions|fintrak_cache_snapshot_v1|TABLE_LIMIT|PAGE_SIZE|render_status|cache_snapshot" .
rg -n "@app\.route|def api_|request\.is_json|client_action_id|balance_mode|recompute_balance_entries_after|balance_entry_mode" app.py
rg -n "style=|text-white-50|text-light" templates static app.py
```

Syntax/template checks to run after code changes:

```bash
python -B -c "import ast, pathlib; [ast.parse(pathlib.Path(p).read_text(encoding='utf-8'), filename=p) for p in ('app.py','forms.py')]; print('python syntax ok')"
python -B -c "from app import app; [app.jinja_env.get_template(t) for t in app.jinja_env.list_templates() if t.endswith('.html')]; print('templates ok')"
node --check static\js\script.js
node --check static\js\offline_queue.js
node --check static\js\sync_status.js
node --check static\js\browser_cache.js
node --check static\js\balance.js
node --check static\js\splits.js
node --check static\js\analytics.js
node --check static\js\balance_analytics.js
node --check static\js\flash.js
node --check static\js\auth_status.js
```

Known honest limitation: duplicate-proof queue retry is strongest only where the backend uses `client_action_id` or `client_actions`. Other queued write routes are ordered and durable, but still need server-side idempotency for complete retry-after-success protection.
