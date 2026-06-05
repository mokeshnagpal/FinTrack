# FinTrak

FinTrak is a Flask web app for personal money tracking. It helps you record expenses, manage cash balance, schedule recurring entries, split shared bills, plan trips, and review analytics.

The app uses:

- Flask and Jinja for the backend and pages
- Firestore for saved data
- WTForms and CSRF protection for forms
- Bootstrap plus shared UI macros for consistent screens
- Vanilla JavaScript for page behavior
- Unit tests for forms, templates, pagination, and money math

## Main Features

| Area | What it does |
| --- | --- |
| Transactions | Add, edit, delete, search, sort, and paginate expenses. |
| Balance | Add money, sync to an exact balance, edit rows, delete rows, and recalculate the running balance. |
| Recurring | Create recurring expenses and recurring balance additions. |
| Split Bills | Track what each person spent, calculate each equal share, and record your share as a transaction. |
| Trips | Track fixed-cost trips or connect a trip to a split bill. |
| Analytics | View spending and balance charts. |
| Settings | Manage categories, split people, account password, username, and view-only access. |
| View-only Mode | Let someone view data without allowing writes. |

## Money Logic

Shared finance logic lives in `ledger.py`. It is kept separate from Flask and Firestore so it is easy to test.

| Action | Balance effect |
| --- | --- |
| Add an expense of Rs. 100 | Balance decreases by Rs. 100. |
| Edit an expense from Rs. 100 to Rs. 80 | Balance increases by Rs. 20. |
| Delete an expense of Rs. 100 | Balance increases by Rs. 100. |
| Add Rs. 500 to balance | Balance increases by Rs. 500. |
| Sync balance to an exact value | Delta is new balance minus old balance. |
| Record a split share | Creates a Trip-category transaction for the calculated share. |

Split bill math:

```text
each_share = total_spent / number_of_people
person_balance = person_spent - each_share
```

If `person_balance` is positive, that person should receive money. If it is negative, that person should give money.

## Project Structure

```text
app.py              Flask routes, Firestore access, and page rendering
forms.py            WTForms form definitions and validators
constants.py        Table limits and app constants
ledger.py           Pure money and split math
pagination.py       Shared pagination helper
templates/          Jinja pages and UI macros
static/css/         App styles and light/dark theme variables
static/js/          Page scripts
tests/              Unit and template tests
run_tests.py        Test runner
```

## Local Setup

1. Create and activate a virtual environment.

```bash
python -m venv venv
venv\Scripts\activate
```

2. Install dependencies.

```bash
pip install -r requirements.txt
```

3. Set environment variables.

```bash
set FLASK_SECRET=your-random-secret
set FIREBASE_CREDENTIALS={"type":"service_account",...}
set ADMIN_USER=you@example.com
set VIEW_PASS=temporary-view-only-password
```

4. Run the app.

```bash
set FLASK_APP=app.py
flask run
```

Open `http://127.0.0.1:5000`.

## Tests

Run all tests from the project root:

```bash
python run_tests.py
```

The test suite checks:

- Money and split calculations
- Login and password form validation
- Pagination windows
- Jinja template compilation

Useful syntax checks:

```bash
python -B -c "import ast, pathlib; [ast.parse(pathlib.Path(p).read_text(encoding='utf-8'), filename=p) for p in ['app.py','forms.py','ledger.py','constants.py','pagination.py','run_tests.py']]"
node --check static\js\script.js
node --check static\js\balance.js
node --check static\js\analytics.js
node --check static\js\balance_analytics.js
node --check static\js\splits.js
node --check static\js\utils.js
node --check static\js\flash.js
node --check static\sw.js
```

## Environment Variables

| Variable | Purpose |
| --- | --- |
| `FLASK_SECRET` | Required. Signs sessions and CSRF tokens. |
| `FIREBASE_CREDENTIALS` | Required. Firebase service account JSON. |
| `ADMIN_USER` | Comma-separated admin usernames or emails. |
| `VIEW_PASS` | Optional starting password for view-only login. |
| `FORCE_HTTPS` | Use `true` in production behind HTTPS. |
| `SESSION_LIFETIME_HOURS` | Login duration. Default is 12. |
| `OCCURRENCE_WINDOW_SECS` | Duplicate window for recurring entries. |
| `ENABLE_DEBUG_ROUTES` | Keep off in production. |
| `LOG_LEVEL` | Logging level. Default is `INFO`. |

## UI Notes

- Shared UI components live in `templates/macros/ui.html`.
- Light and dark mode use CSS variables in `static/css/styles.css`.
- Main tables, cards, forms, and toolbars are responsive for mobile and desktop.
- Client-side validation shows toast messages before invalid forms submit.
- Server-side validation still protects every write route.

## Production Checklist

- Use a strong `FLASK_SECRET`.
- Store Firebase credentials securely on the host.
- Set `FORCE_HTTPS=true` when served over HTTPS.
- Keep Flask debug mode off.
- Create Firestore indexes if Firestore asks for them.
- Smoke-test login, view-only login, transactions, balance, recurring, splits, trips, settings, analytics, dark mode, and mobile layout.

## Service Worker

`static/sw.js` clears old browser caches and unregisters older offline workers. The current app does not queue offline writes.
