# FinTrak

FinTrak is a Flask and Firestore finance tracker for daily spending, recurring expenses, balance history, analytics, categories, and read-only account access.

The app is built as a server-rendered Flask application with Jinja templates, Bootstrap, Chart.js, custom CSS, and a small browser-side action queue for slow or cold Render starts.

## What It Supports

- Add, edit, delete, paginate, and export transactions.
- Search transactions and sort the transaction table by date, description, category, or amount.
- Queue transaction add, edit, and delete actions in the browser when the backend is slow.
- Sync queued transaction actions to Render in the background.
- Prevent duplicate queued writes with `client_action_id` and a per-user action log.
- Manage recurring expense rules with create, edit, and delete flows.
- Track balance with add, sync, undo, chart, and ledger history.
- Review analytics with summary metrics, trends, category breakdowns, insights, raw transactions, and CSV export.
- Manage categories from the Management page.
- Change the view-only password from the Management page.
- Use `VIEW_PASS` as the first view-only fallback until a database password is saved.
- Display and input user-facing dates/times in India time.
- Use responsive layouts, dark mode, readable tables, and reusable confirmation dialogs.

## Architecture

- Backend: Flask, Flask-WTF, WTForms, Firebase Admin SDK, Firestore.
- Frontend: Jinja templates, Bootstrap 5, Chart.js, custom CSS, vanilla JavaScript.
- Storage: Firestore user documents with per-user subcollections.
- Queue: `localStorage` stores pending browser actions until the backend accepts them.
- Caching: in-process TTL cache reduces repeated Firestore reads for categories and view-only password status.
- Auth: full sessions and view-only sessions use separate permission paths.

## Key Security Behaviors

- `FLASK_SECRET` is required at startup.
- Passwords are verified using Werkzeug hashes, with bcrypt support for existing bcrypt hashes.
- View-only password changes are stored as secure hashes in Firestore.
- CSRF protection is enabled for mutating requests.
- JSON mutation APIs include CSRF headers from the frontend.
- Read-only sessions are blocked from write routes and write APIs.
- Redirect targets are checked before use.
- Session cookies are HTTP-only, SameSite `Lax`, and secure when `FORCE_HTTPS=true`.
- Legacy `/view` accepts passwords only by POST, not URL query parameters.

## Browser Queue

Transaction create, edit, and delete forms are marked with `data-offline-queue`.

When a user submits one of these forms:

1. The action is saved to `localStorage`.
2. The UI gives immediate feedback.
3. The browser tries to submit the action to Render.
4. If the request fails or times out, the action stays queued.
5. When the backend responds later, queued actions sync one by one.

Create actions use `client_action_id` as the Firestore transaction document id. Edit and delete actions write to a per-user `client_actions` log. Balance entries use action-specific notes so retries do not repeatedly apply the same balance delta.

If browser storage is unavailable, the app falls back to normal form submission.

## Caching

The app uses a small in-process TTL cache for:

- category settings
- view-only password hash status

The cache reduces repeated Firestore reads during normal page loads. Category and view-only password updates refresh the relevant cached value immediately.

Configure the TTL with `CACHE_TTL_SECONDS`. Default: `300`.

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
set ADMIN_USER=admin
set VIEW_PASS=initial-view-only-password
```

Run locally:

```bash
set FLASK_APP=app.py
flask run
```

Open `http://127.0.0.1:5000`.

## Environment Variables

- `FLASK_SECRET`: required Flask session and CSRF signing secret.
- `FIREBASE_CREDENTIALS`: required Firebase service account JSON string.
- `ADMIN_USER`: comma-separated usernames allowed for admin password setup.
- `VIEW_PASS`: optional initial view-only password fallback.
- `FORCE_HTTPS`: set to `true` behind HTTPS so session cookies are secure.
- `SESSION_LIFETIME_HOURS`: login duration. Default: `12`.
- `OCCURRENCE_WINDOW_SECS`: recurring duplicate-detection window. Default: `60`.
- `CACHE_TTL_SECONDS`: settings/category cache duration. Default: `300`.
- `FIRESTORE_TIMEOUT_SECONDS`: timeout for critical Firestore reads used during auth/settings rendering. Default: `8`.
- `ENABLE_DEBUG_ROUTES`: optional recurring diagnostics route switch. Keep unset or `false` in production.
- `LOG_LEVEL`: Flask log level. Default: `INFO`.
- `FLASK_DEBUG`: local debug flag. Keep disabled in production.

## View-Only Password Rules

If no Firestore view-only password exists, FinTrak uses `VIEW_PASS`.

After a user changes the view-only password in Management, the Firestore hash becomes the active password. At that point the password cannot be copied back from the app, because only the hash is stored.

The copy button is available only while the active password is still the environment fallback.

## Production Checklist

- Use a long random `FLASK_SECRET`.
- Store `FIREBASE_CREDENTIALS` securely in the hosting provider.
- Set `FORCE_HTTPS=true` when deployed behind HTTPS.
- Run with Gunicorn or another WSGI server.
- Keep `FLASK_DEBUG` disabled.
- Restrict Firebase service account permissions to the app's needs.
- Create any Firestore indexes requested by range/order queries.
- Test full login and view-only login.
- Test transaction add, edit, delete, queue retry, and background sync.
- Test recurring rules, categories, view-only password change, balance actions, analytics, CSV export, dark mode, and mobile layouts.

## Verification

Frontend JavaScript syntax checks:

```bash
node --check static\js\script.js
node --check static\js\offline_queue.js
node --check static\js\balance.js
node --check static\js\analytics.js
node --check static\js\flash.js
```

Python syntax check in an environment with Python installed:

```bash
python -m compileall app.py forms.py PASS.py
```

## Known Scaling Note

The transaction page uses Firestore cursor pagination instead of `.offset()`. Search is implemented inside the current sorted Firestore stream, so it avoids full collection scans by default. If transaction volume becomes very large and search must cover every historical record, add a dedicated search index such as Algolia, Typesense, Meilisearch, or a normalized Firestore search collection.
