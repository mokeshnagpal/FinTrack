# FinTrak

FinTrak is a fully online Flask + Firestore finance tracker for personal spending, balances, recurring rules, split bills, trips, analytics, admin settings, and view-only access.

The app is server-rendered with Jinja templates, Bootstrap 5, custom CSS, vanilla JavaScript, Chart.js, the Firestore Admin SDK, and direct Firestore reads/writes. Firestore is the single source of truth.

## Architecture

FinTrak is intentionally online-only:

- Page loads render from current Firestore-backed server state.
- CRUD actions write directly to Firestore through Flask routes.
- API endpoints read fresh Firestore values for analytics, balances, splits, trips, transactions, and settings.
- The browser does not maintain an offline action queue or cached application snapshot.
- The server does not keep an in-memory application data cache.
- There is no service worker, Cache API usage, PWA manifest, background sync, or offline login flow.

## Main Features

| Area | What the code supports |
|---|---|
| Transactions | Add, edit, delete, search, sort, and view transaction history. |
| Balance | Add delta entries, set an absolute balance, edit/delete displayed balance rows, and recalculate later rows. |
| Recurring | Expense recurring rules and balance recurring rules with create/edit/delete flows. |
| Splits | Split documents, live/saved status, split entries, per-person totals, and trip connection/disconnection flows. |
| Trips | Fixed-budget trips and split-spend trips, with create/edit/delete/disconnect flows. |
| Analytics | Spend analytics, balance analytics, Chart.js charts, summary cards, tables, and CSV export. |
| Management | Categories, split people, view-only password, account username/email, and account password management. |
| View-only mode | Read-only access with write controls hidden or blocked server-side. |

## Data Flow

1. Users authenticate through Flask.
2. Login checks the submitted credentials against Firestore-backed account data.
3. Standard page requests render server-side Jinja templates.
4. Form submissions and JSON APIs validate input server-side and then read/write Firestore directly.
5. Analytics pages call Firestore-backed API endpoints each time they refresh.
6. If the backend or network is unavailable, the affected request fails visibly instead of falling back to stale local data.

## Balance Ledger Behavior

Balance rows use two related fields:

| Field | Meaning |
|---|---|
| `type` | The broad row source, such as `add`, `sync`, transaction edit/delete adjustment, or transaction-created balance movement. |
| `balance_mode` | The editable balance mode marker: `add` or `sync`. |

The legacy value `sync` in balance data means an absolute balance anchor. It is not an offline/background synchronization system.

## UI And Components

The app uses a shared base layout, shared CSS variables, Bootstrap classes, and Jinja macros in `templates/macros/ui.html`.

Reusable UI covers:

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

## Security Notes

| Area | Current behavior |
|---|---|
| Flask secret | `FLASK_SECRET` is required for sessions/CSRF. |
| Admin/full password | Stored as a Werkzeug-compatible password hash in Firestore. |
| View-only password | Uses Firestore hash after it is set; can fall back to `VIEW_PASS` if no Firestore value exists. |
| CSRF | Enabled for standard Flask forms and JSON requests where the frontend sends it. |
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

## Verification

Useful checks after changes:

```bash
python -B -c "import ast, pathlib; [ast.parse(pathlib.Path(p).read_text(encoding='utf-8'), filename=p) for p in ('app.py','forms.py')]; print('python syntax ok')"
python -B -c "from app import app; [app.jinja_env.get_template(t) for t in app.jinja_env.list_templates() if t.endswith('.html')]; print('templates ok')"
node --check static\js\script.js
node --check static\js\splits.js
node --check static\js\analytics.js
node --check static\js\balance_analytics.js
node --check static\js\balance.js
node --check static\js\flash.js
```
