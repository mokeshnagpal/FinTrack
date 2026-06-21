# FinTrak

FinTrak is a Flask + Firestore personal finance web app. It combines server-rendered pages, authenticated user flows, and Firestore-backed collections for transactions, balances, recurring rules, split payments, trips, and analytics.

## What FinTrak does

- Tracks daily transactions with categories, notes, and tags.
- Stores running balances and recurring balance rules.
- Supports split expenses and multi-person trips.
- Provides analytics dashboards for spending and balance trends.
- Includes management tools for categories, split participants, and password controls.
- Offers a view-only access mode for safe shared access.

## Architecture

### Backend

- `app.py` is the single Flask application entrypoint.
- Uses `firebase-admin` and Firestore as the primary persistent datastore.
- Renders HTML through Jinja templates in `templates/`.
- Handles form validation via `Flask-WTF` and `WTForms`.
- Supports session-based user state, login, logout, view-only sessions, and duplicate submission protection.

### Frontend

- Static files live in `static/`.
- CSS: `static/css/styles.css`.
- JS: reusable client helpers, analytics scripts, balance/transaction UI, and split/trip controls.
- Uses Bootstrap 5 and Chart.js for responsive UI and charts.

### Data model

The app stores data under a top-level Firestore collection:

- `users` — one document per normalized username.

Each user document contains profile-level settings and access controls, plus transactional subcollections.

## Recent cleanup and schema migration

- Balance entries now use explicit `txn_id` for transaction-linked rows.
- The `type` field is enforced on balances: `txn` for transaction rows, `add` for manual adjustments, and `sync` for balance syncs.
- Legacy `note="txn:<id>"` linkage is no longer used for transaction balance mapping.
- Free-text balance notes are stored in `notes`; `note` is preserved only as a display alias for compatibility.
- Temporary CSV export artifacts have been removed from the repository root.

### `users/{username}` document fields

- `categories` — map of category name → access type (`public` or `protected`).
- `split_people` — array of split participant names.
- `view_pass` — hashed password used for view-only login.
- `admin_pass` — hashed admin password.
- `password` — hashed normal login password.
- Optional metadata fields are created/maintained by the app.

### Per-user subcollections

- `transactions` — transaction records.
- `balances` — balance entries.
- `recurring` — recurring transaction rules.
- `recurring_balances` — recurring balance rules.
- `splits` — split definitions.
- `trips` — trip entries.

### Transaction documents

Each transaction document typically contains fields such as:

- `amount`
- `category`
- `description`
- `timestamp`
- `created_at`
- `updated_at`
- `cost_type` (e.g. `individual`, `split`)
- `split_id` (when a transaction belongs to a split)
- `split_title` (display helper for split-linked transactions)

### Saved transaction templates

Saved transaction templates are stored under `users/{username}/saved_transactions` and include:

- `amount`
- `category`
- `description`
- `created_at`
- `updated_at`

These templates can be created, edited, deleted, and submitted to the main `transactions` collection as normal transaction entries.

### Split documents

- `splits/{split_id}` store split metadata, including participant list and totals.
- Each split may include a subcollection of entries or be referenced from transactions.

### Trip documents

- `trips/{trip_id}` store trip details, including travel-related costs and assignment to splits.
- Trips can create split expenses using `cost_type=split`.

## Visibility & Action Rules

### Complete Final Visibility & Action Matrix

| Record Type           | Transaction Table | Balance Table Entry       | Editable from Transaction Table | Editable from Balance Table | Delete Allowed | Notes                                                                      |
| --------------------- | ----------------- | ------------------------- | ------------------------------- | --------------------------- | -------------- | -------------------------------------------------------------------------- |
| Normal Transaction    | `txn-spent`       | `(txn, txn-add)`          | ✅ Yes                           | ✅ Yes                       | ✅ Yes          | Edit/Delete from either table updates both transaction and balance records |
| Recurring Transaction | `recurring`       | `(txn, recurring)`        | ✅ Yes                           | ✅ Yes                       | ✅ Yes          | Behaves exactly like normal transaction after generation                   |
| Split Transaction     | `split`           | `(txn, split)`            | ❌ No                            | ❌ No                        | ❌ No           | Only "View Split" action available                                         |
| Manual Balance Add    | ❌ Not Present     | `(balance, balance-add)`  | ❌ N/A                           | ✅ Yes                       | ✅ Yes          | Exists only in Balance Table                                               |
| Balance Sync          | ❌ Not Present     | `(balance, balance-sync)` | ❌ N/A                           | ✅ Yes                       | ✅ Yes          | Stores adjustment `(desired_balance - current_balance)`                    |
| Recurring Balance     | ❌ Not Present     | `(balance, recurring)`    | ❌ N/A                           | ✅ Yes                       | ✅ Yes          | Generated from recurring balance rule                                      |

---

### Transaction Table

| mode_name   | Source                                    | Editable | Delete Allowed |
| ----------- | ----------------------------------------- | -------- | -------------- |
| `txn-spent` | Normal transaction from Transaction Page  | ✅        | ✅              |
| `recurring` | Generated from recurring transaction rule | ✅        | ✅              |
| `split`     | Generated from Split Module               | ❌        | ❌              |

Actions:

| mode_name   | Actions              |
| ----------- | -------------------- |
| `txn-spent` | View / Edit / Delete |
| `recurring` | View / Edit / Delete |
| `split`     | View Split           |

---

### Balance Table

| Balance (type, mode_name) | Source                  | Editable | Delete Allowed | Actions              |
| ------------------------- | ----------------------- | -------- | -------------- | -------------------- |
| `(txn, txn-add)`          | Normal Transaction      | ✅        | ✅              | View / Edit / Delete |
| `(txn, recurring)`        | Recurring Transaction   | ✅        | ✅              | View / Edit / Delete |
| `(txn, split)`            | Split Transaction       | ❌        | ❌              | View Split           |
| `(balance, balance-add)`  | Manual Balance Addition | ✅        | ✅              | Edit / Delete        |
| `(balance, balance-sync)` | Balance Sync Adjustment | ✅        | ✅              | Edit / Delete        |
| `(balance, recurring)`    | Recurring Balance Rule  | ✅        | ✅              | Edit / Delete        |

---

### Transaction → Balance Mapping

| Transaction mode_name | Balance Record Created |
| --------------------- | ---------------------- |
| `txn-spent`           | `(txn, txn-add)`       |
| `recurring`           | `(txn, recurring)`     |
| `split`               | `(txn, split)`         |

---

### Records Visible Only in Balance Table

These records never appear in Transaction History:

| Balance (type, mode_name) |
| ------------------------- |
| `(balance, balance-add)`  |
| `(balance, balance-sync)` |
| `(balance, recurring)`    |

---

### Records Visible in Both Tables

| Transaction Table | Balance Table      |
| ----------------- | ------------------ |
| `txn-spent`       | `(txn, txn-add)`   |
| `recurring`       | `(txn, recurring)` |
| `split`           | `(txn, split)`     |

---

### Edit/Delete Synchronization Rules

#### Normal Transaction

Transaction:

```text
txn-spent
```

Balance:

```text
(txn, txn-add)
```

Rules:

* Edit from Transaction Table → update linked Balance row.
* Edit from Balance Table → update linked Transaction row.
* Delete from Transaction Table → delete linked Balance row.
* Delete from Balance Table → delete linked Transaction row.

---

#### Recurring Transaction

Transaction:

```text
recurring
```

Balance:

```text
(txn, recurring)
```

Rules:

* Behaves exactly like normal transaction.
* Edit/Delete from either table updates both records.

---

#### Split Transaction

Transaction:

```text
split
```

Balance:

```text
(txn, split)
```

Rules:

* Cannot edit from Transaction Table.
* Cannot edit from Balance Table.
* Cannot delete from Transaction Table.
* Cannot delete from Balance Table.
* Only action available:

```text
View Split
```

* User must modify through Split Module.
* Split changes automatically update linked transaction and balance rows.

---

### Balance Sync Rule

Current Balance:

```text
x
```

Desired Balance:

```text
y
```

Stored Value:

```text
y - x
```

Example:

```text
Current Balance = 500
Desired Balance = 650

Stored Adjustment = 150
```

NOT:

```text
650
```

Stored as:

```text
(balance, balance-sync)
```

---

### Final Allowed Combinations

| type      | mode_name      |
| --------- | -------------- |
| `txn`     | `txn-add`      |
| `txn`     | `recurring`    |
| `txn`     | `split`        |
| `balance` | `balance-add`  |
| `balance` | `balance-sync` |
| `balance` | `recurring`    |

These are the only valid combinations that should exist after migration and throughout the application.

## Core feature flow

### Authentication

- Users log in with username and password via the `/login` route.
- Authenticated sessions are stored in Flask session data.
- Admin users may be provisioned via environment variables:
  - `ADMIN_USER` — comma-separated list of admin usernames.
  - `ADMIN_PASS` — fallback admin password used for env-admin logins.
- View-only access is supported via `view_pass` and `VIEW_PASS` as a fallback.

### View-only mode

- Non-privileged view-only sessions can access read-only pages.
- POST requests are blocked while `session['view_only']` is active.
- Allowed view-only pages include dashboard and analytics routes.
- This is useful for sharing financial summaries without edit access.

### Transactions

- Create / edit / delete transactions from `transactions.html`.
- Transaction operations are routed through APIs like `/api/transactions/create`, `/api/transactions/<tx_id>/update`, and `/api/transactions/<tx_id>/delete`.
- Duplicate form submissions are protected by a session-based timeout mechanism: identical payloads within a short period are rejected as duplicates.

### Balances

- Add balance rows on `balance.html`.
- Sync balances with Firestore using `/api/balance/sync`.
- Recurring balances are handled via `recurring_balances` and can generate future balance entries.

### Recurring rules

- Recurring transaction rules are managed in `recurring.html`.
- Recurring balances are managed in a separate recurring balance form.
- The app stores recurring rules in Firestore under `users/{username}/recurring`.

### Splits and trips

- `splits.html` lists active splits and split history.
- `split_detail.html` shows individual split entries and participants.
- `trips.html` lists trips and lets users assign costs to split payments.
- Trip costs may be single-user or shared costs.
- Split participants are managed from the management page.

### Management

- The management page (`/management`) controls:
  - category names and default category selection
  - split participant names
  - view-only password configuration
- Admin users can edit and delete categories or split persons.

### Analytics

- `analytics.html` and `balance_analytics.html` present charts for spending and balance trends.
- The analytics pages use Firestore data pulled by the backend and rendered with Chart.js.

## Page structure

`templates/` includes:

- `index.html` — main dashboard.
- `login.html` — login form.
- `view.html` — view-only entry.
- `transactions.html` — transaction list and editor.
- `balance.html` — balance entry page.
- `recurring.html` — recurring planner.
- `splits.html` — split overview.
- `split_detail.html` — split details.
- `trips.html` — trip management.
- `management.html` — admin settings and user management.
- `analytics.html` — spending analytics.
- `balance_analytics.html` — balance analytics.
- `forgot_password.html`, `reset_password.html`, `verify_otp.html` — admin password reset flow.
- `base.html` — shared layout and UI macros.
- `macros/ui.html` — shared UI components.

## Static assets

`static/` contains:

- `css/styles.css` — app styling.
- `js/analytics.js`, `js/balance_analytics.js`, `js/balance.js`, `js/flash.js`, `js/script.js`, `js/splits.js`, `js/utils.js` — UI helpers and page scripts.
- `icons/` — icon assets.

## Environment variables

Set these for local development and deployment:

- `FLASK_SECRET` — secret key for Flask sessions and CSRF protection.
- `FIREBASE_CREDENTIALS` — JSON credentials string for Firestore service account.
- `ADMIN_USER` — comma-separated admin usernames.
- `ADMIN_PASS` — fallback admin password for env-admin users.
- `VIEW_PASS` — optional fallback view-only password.
- `FORCE_HTTPS` — if set, app may enforce HTTPS behavior.
- `SESSION_LIFETIME_HOURS` — session expiry duration.
- `FIRESTORE_TIMEOUT_SECONDS` — Firestore request timeout.
- `ENABLE_DEBUG_ROUTES` — optionally enables debug routes.

## Running locally

1. Create and activate a virtual environment:

```powershell
python -m venv venv
venv\Scripts\activate
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Configure environment variables:

```powershell
set FLASK_APP=app.py
set FLASK_SECRET=replace-with-secret
set FIREBASE_CREDENTIALS={"type":"service_account", ... }
set ADMIN_USER=user@example.com
set ADMIN_PASS=youradminpassword
set VIEW_PASS=optionalviewpassword
```

4. Start the app:

```powershell
flask run
```

5. Open the browser:

```text
http://127.0.0.1:5000

## Repair scripts

- `scripts/repair_preview.py`: safe preview and optional apply for the balance->transaction repair flow. It now generates preview exports on demand and does not rely on repository-committed temporary CSV artifacts.
- By default it runs as a dry-run and will not write to Firestore. To apply updates set the environment variable `ALLOW_FIRESTORE_WRITES=1` and run with `--apply`. The script enforces a conservative Firestore operation limit of 50000 combined reads/writes and will refuse to apply if the estimated operations exceed that limit.
```

## Deployment notes

- The app is compatible with WSGI servers like Gunicorn.
- In production, do not store `FIREBASE_CREDENTIALS` in source control.
- Use secure session secrets and HTTPS wherever possible.
- Ensure Firestore region and project settings match your `FIREBASE_CREDENTIALS`.

## Firestore schema reference

### Top-level collection

- `users` — one document per normalized username (email)

## Current app state and recent changes

This website currently supports:

- transaction history with edit/delete workflows
- saved transaction templates that can be added, edited, deleted, and submitted as regular transactions
- split expense management with split-linked transaction navigation
- running balances and balance sync entries
- recurring transaction and balance rules
- analytics dashboards and spending charts

Recent changes included:

- added support for `users/{username}/saved_transactions` to store saved templates.
- added `split_id`, `split_title`, and `split_url` metadata so split-linked transactions can be displayed with a "View Split" action.
- restricted split-linked transactions so they can only be managed from the split detail page, preventing edit/delete from the general history UI.
- preserved 12-row pagination behavior and count-based page math for both transactions and saved transaction templates.
- added explicit transaction/balance sync logic so updates and deletions resynchronize associated balance entries.
- implemented duplicate request protection for transaction update/delete actions.

### User document (`users/{username}`) fields

- `password` — hashed login password
- `view_pass` — hashed view-only password (optional)
- `admin_pass` — hashed admin password (optional)
- `categories` — map of category names to access type
- `split_people` — array of split participant names
- `default_category` — default category name (optional)

### Per-user subcollections

- `transactions` — expense/income records
- `balances` — running balance entries
- `recurring` — recurring transaction rules
- `recurring_balances` — recurring balance rules
- `splits` — split payment definitions
- `trips` — trip records

### Splits subcollections

- `splits/{split_id}/entries` — individual split entries for each participant
- `users/{username}/saved_transactions/{template_id}` — saved transaction templates

### Example Firestore paths

- `users/nagpalmokesh@gmail.com`
- `users/nagpalmokesh@gmail.com/transactions/{txn_id}`
- `users/nagpalmokesh@gmail.com/splits/{split_id}`
- `users/nagpalmokesh@gmail.com/splits/{split_id}/entries/{entry_id}`


## Notes on duplicate request handling

- Duplicate submissions are now blocked using a session-based payload signature and timeout window.
- This prevents accidental double-posts on transaction creation/update/delete from the same session.

## Table behaviour, pagination, sorting and transaction search

- Per-table pagination: each table uses a 12-row page size. The UI loads a limited set of documents (up to `page * 12`) and displays a single page slice in the table. Pagination widgets are independent per table so each table maintains its own current page and controls.
- Client-side sorting: clicking a sortable column header sorts only the rows currently loaded into the table (the 12 rows shown or the set of rows present in the DOM). Sorting is performed in-memory in the browser; no additional sort parameters or requests are sent to the server.
- In-memory sorting guarantees instant responses for header clicks and avoids requiring composite Firestore indexes for ordered queries. For larger datasets, the server still provides paginated results; the client sorts only the visible page.
- Transactions search: searching transactions is performed server-side (Firestore queries) to find matching documents by description, category, or amount. Search endpoints return a paginated set of matching rows; once results are received, the client will render and allow in-memory sorting of the returned page. Common search patterns implemented:
  - Prefix search on `description` using range queries (`description >= term` and `description <= term + "\uf8ff"`).
  - Exact-match queries for `category` and `amount` where applicable.
- UX notes: split-linked transactions include `split_id` and `split_url` metadata and are shown with a "View Split" action; edit/delete are restricted for split-linked rows and must be handled from the split detail page.

## Math and pagination formulas

- Page count: `total_pages = ceil(total_items / 12)`
- Display range: `from = ((page - 1) * per_page) + 1`
- Display upper bound: `to = min(page * per_page, total_items)`
- Transaction update delta: `balance_delta = round(old_amount - new_amount, 2)`
- Split share: `share_amount = round(total_spent / num_people, 2)`
- Amount normalization: transaction amounts are rounded to two decimals for display and storage.

## Troubleshooting

- If login fails, verify `ADMIN_USER` and `ADMIN_PASS` values and the stored Firestore user record.
- If Firestore access fails, confirm your `FIREBASE_CREDENTIALS` JSON is valid and has the correct permissions.
- For session issues, ensure `FLASK_SECRET` is set and stable across app restarts.
- If analytics or chart data are missing, refresh the page after adding transactions and balances.

## Project files

Key files and folders:

- `app.py` — Flask backend and route handlers.
- `forms.py` — Flask-WTF form definitions.
- `requirements.txt` — Python dependencies.
- `templates/` — HTML templates.
- `static/` — CSS and JavaScript assets.
- `README.md` — this documentation.

---

If you want, I can also add a separate `README-schema.md` with exact Firestore document field names and example payloads.
