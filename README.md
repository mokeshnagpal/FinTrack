# FinTrak - Finance Tracker with Recurring Rules & Splits

A production-ready Flask and Firestore finance tracker for daily spending, recurring expenses, balance history, split documents, analytics, categories, and read-only account access.

The app is built as a server-rendered Flask application with Jinja templates, Bootstrap 5, Chart.js, custom CSS, and client-side offline queue for resilience during slow backend responses.

## ✅ Core Features (All Verified)

### Transactions (CRUD Complete & Unlocked)
- ✓ **Add** transactions with amount, description, category, date, and time
- ✓ **Edit** any historical transaction with automatic, real-time balance ledger calculations
- ✓ **Delete** any transaction with live cascade balance adjustments
- ✓ **View** all transactions with pagination (default 15 per page)
- ✓ **Search** transactions by description or category
- ✓ **Sort** by date, description, category, or amount
- ✓ **Data Validation**: Amount parsing with negative rejection, description max 120 chars
- ✓ **Logging**: All CRUD ops logged at INFO/WARNING level with user context

### Balance Tracking (CRUD Complete)
- ✓ **Add** manual balance entries (positive or negative amounts)
- ✓ **Sync** absolute balance value with cascading shifts to maintain history
- ✓ **Edit** balance entries with impact calculation
- ✓ **Delete/Undo** entries (latest first) with automatic rebalancing
- ✓ **Chart** with daily/monthly/yearly periods
- ✓ **History** ledger with most recent 50 entries, formatted in IST
- ✓ **Data Validation**: Money parsing supports negative, max 999,999,999
- ✓ **Logging**: Balance operations logged with delta and resulting balance

### Recurring Rules (CRUD Complete)
- ✓ **Create** expense or balance-add rules with frequency (daily/weekly/monthly/yearly)
- ✓ **Edit** rules to modify amount, description, category, start date
- ✓ **Delete** rules by ID
- ✓ **View** newest 12 recurring rules per table (compact display)
- ✓ **Auto-apply** new occurrences daily (cron-like within request)
- ✓ **Duplicate Prevention** via client_action_id + server-side dedup
- ✓ **Data Validation**: Amounts, descriptions, frequency selection validated
- ✓ **Logging**: Rule creation, updates, deletions, and auto-apply events logged

### Split Documents (CRUD Complete)  
- ✓ **Global Splits Sidebar Drawer**: A premium left-side drawer with smooth slide transitions and real-time search filtering, loaded globally to browse and switch split documents instantly.
- ✓ **Create** split documents (e.g., trips, shared expenses), defaulting to `is_live=True` at creation.
- ✓ **Edit** split titles with a bug fix that preserves the original active/live status.
- ✓ **Delete** splits and all associated entries.
- ✓ **Add Entries** to splits (amount, person, category, description).
- ✓ **Edit Entries** per person with validation.
- ✓ **Delete Entries** with automatic totals refresh.
- ✓ **Totals** calculated per person (sum of their entries).
- ✓ **Render Awake vs. Sleep (Offline Backup)**: Gracefully falls back to browser localStorage caching for the splits navigator when the Render server is sleeping/offline, displaying seamless warning badges.
- ✓ **Queue Support**: All split entry write operations are buffered in IndexedDB `offline_queue` during Render sleep states, auto-syncing when the server wakes up.
- ✓ **Data Validation**: All amounts, persons, and descriptions validated.
- ✓ **Logging**: Split and entry operations logged at INFO/WARNING level.

### Trips Management (CRUD Complete & Unlocked) [NEW]
- ✓ **Create** trip documents with Name, Start/End Dates, Description, and Photos Album URL.
- ✓ **Fixed Budget Mode**: Set a fixed, manually entered approximate cost.
- ✓ **Split spend Mode**: Dynamically link the trip to a Split account where the approximate cost of the trip displays the net cost per participant (Sum of entries / Number of unique participants). Creating a split-spend trip automatically creates a new Split document of the same name.
- ✓ **Bidirectional Disconnection**: Disconnect the split/trip connection from either the Trips page or the Splits table. Prompts the user to decide whether to delete the connected document or preserve it disconnected.
- ✓ **Offline & Queue Caching**: Caches the last 12 trip documents inside `localStorage` for immediate fallback rendering when Render is offline or sleeping, with background queue sync.

### Analytics & Reporting (All Verified)
- ✓ **Summary Metrics**: Total spend, transaction count, average per transaction
- ✓ **Trends**: Month-over-month spending comparison
- ✓ **Category Breakdown**: Pie chart and table of spending by category
- ✓ **Insights**: AI-generated summary insights
- ✓ **Raw Transactions**: Full transaction table with sortable columns
- ✓ **CSV Export**: Download transaction data for external analysis
- ✓ **Data Validation**: Date ranges, period filters validated
- ✓ **Logging**: Analytics queries logged for performance monitoring

### Management (Settings & Admin)
- ✓ **Categories**: Add, edit, delete custom expense categories
- ✓ **Split People**: Add, edit, delete people for splits
- ✓ **View-Only Password**: Create, change, reveal current password
- ✓ **Account**: Change username/email and password
- ✓ **Data Validation**: All inputs validated with regex and length checks
- ✓ **Logging**: Settings changes logged with user context

## 📱 Responsive Design (Mobile & Desktop Verified)

### Breakpoints & Behavior
| Screen | Media Query | Behavior |
|--------|-------------|----------|
| **Mobile** | max-width: 575px | Single-column layout, full-width buttons, card-based table view |
| **Tablet** | 576px - 767px | 2-column grid for analytics, compact controls |
| **Laptop** | 768px - 1199px | 3-column analytics grid, side-by-side forms |
| **Large** | 1200px+ | Full 4-5 column grids, optimal spacing |

### UI Elements Verified
- ✓ **Tables**: Auto-convert to card layout on mobile with data-label attributes
- ✓ **Forms**: Stack vertically on mobile, responsive column widths on desktop
- ✓ **Navigation**: Collapsible burger menu on mobile, full navbar on desktop
- ✓ **Charts**: Height adjusts (240px mobile → 300px tablet → 380px desktop)
- ✓ **Buttons**: Min height 48px mobile (WCAG touch target), 42px desktop
- ✓ **Grid**: Bootstrap grid with auto-fit and minmax for responsive cards

## 🔐 Data Validation & Error Handling (All Verified)

### Backend Validation
| Input | Validation | Error Handling |
|-------|-----------|-----------------|
| **Amount** | Float, finite, max 999M, negative check | ValueError → 400 response |
| **Description** | String, max 120 chars, required | ValueError → 400 response |
| **Category** | Exists in user categories, case-insensitive | ValueError → 400 response |
| **Person (Splits)** | Exists in split people list | ValueError → 400 response |
| **Note** | String, max 120 chars, optional | ValueError → 400 response |
| **Email/Username** | Regex pattern (email format) | ValueError → 400 response |
| **Password** | Min 7 chars, 1 uppercase, 1 lowercase, 1 digit | ValueError → 400 response |
| **Date** | ISO format (YYYY-MM-DD) | ValueError → None (default) |

### Frontend Validation  
- ✓ HTML5 input attributes (type, step, min, max, maxlength)
- ✓ Browser-side error display in red text
- ✓ Try-catch blocks around fetch calls
- ✓ Empty input checking before API calls

### Logging Coverage
- ✓ **app.logger.info()**: Major operations (create, update, delete, auto-apply)
- ✓ **app.logger.warning()**: Auth failures, validation errors, edge cases
- ✓ **app.logger.exception()**: Firestore failures, unexpected errors
- ✓ **app.logger.debug()**: Config startup, threshold checks
- ✓ **Log Level**: Configurable via LOG_LEVEL env var (default INFO)

## 🎨 UI & Code Quality (All Verified)

### Responsive CSS
- ✓ **4 Media Query Breakpoints**: 1200px, 992px, 768px, 576px
- ✓ **Fluid Typography**: Font sizes use clamp() for smooth scaling
- ✓ **Grid Layouts**: auto-fit, minmax for responsive card grids
- ✓ **Dark Mode**: Full theme support with CSS variables
- ✓ **Accessibility**: Proper heading hierarchy, ARIA labels, focus states

### Code Quality
- ✓ **Variable Naming**: Descriptive names (e.g., `normalized_username`, `is_view_only`, `balance_delta`)
- ✓ **Function Naming**: Verb-noun pattern (e.g., `parse_money()`, `validate_short_text()`)
- ✓ **Code Organization**: Logical sections (config, utils, routes, templates)
- ✓ **Comment Blocks**: Marked with `# ---` for major sections
- ✓ **Docstrings**: Utility functions documented
- ✓ **DRY Principle**: Reusable templates, functions for common tasks
- ✓ **Error Constants**: MAX_MONEY_AMOUNT, MAX_DESCRIPTION_LENGTH defined

### Dropdown UI (Improved)
- ✓ **Smooth animations**: 200ms fade-in on open
- ✓ **Hover effects**: Background color + slide transform
- ✓ **Dark mode**: Enhanced colors and shadows
- ✓ **No underlines**: Removed on all hover states

## 🏗️ Architecture

### Backend Stack
- **Framework**: Flask with Flask-WTF for CSRF protection
- **Database**: Firestore (Google Cloud)
- **ORM**: Direct Firestore Admin SDK (no SQLAlchemy)
- **Forms**: WTForms with custom validators
- **Logging**: Python logging module
- **Password**: Werkzeug hashing (bcrypt compatible)

### Frontend Stack
- **Templates**: Jinja2 (server-side rendering)
- **CSS Framework**: Bootstrap 5 + custom CSS
- **Charts**: Chart.js for balance/analytics graphs
- **State**: localStorage for offline queue (browser cache)
- **Interactivity**: Vanilla JavaScript (no jQuery/Vue)

### Data Flow
1. **User Action** → Form submit or fetch API call
2. **Server Validation** → WTForms or custom validators
3. **Firestore Write** → Document creation/update/delete
4. **Cache Invalidation** → TTL cache cleared for that collection
5. **Response** → JSON (API) or redirect (forms)
6. **Client Update** → Re-render table or show toast

### Caching Strategy
- **In-Process TTL Cache**: Categories, split people, view-only password
- **TTL Duration**: Configurable (default 300 seconds)
- **Eviction**: Per-user cache invalidated on changes
- **Browser Cache**: localStorage for offline queue (separate from server cache)

## 🔐 Security (All Verified)

- ✓ `FLASK_SECRET` required at startup
- ✓ Passwords hashed with Werkzeug (bcrypt legacy support)
- ✓ CSRF protection on all POST/PUT/DELETE routes
- ✓ Read-only sessions blocked from write routes
- ✓ Redirect targets validated with `is_safe_redirect_url()`
- ✓ Session cookies: HTTP-only, SameSite Lax, Secure when FORCE_HTTPS=true
- ✓ Input validation on all user-submitted data
- ✓ Idempotency via client_action_id to prevent duplicate writes

## 📊 Performance & Optimization

- ✓ **Pagination**: Transactions default to 15 per page
- ✓ **Table Limits**: 12 rows per recurring/split table (newest first)
- ✓ **Query Windows**: IST day bounds for efficient range queries
- ✓ **Browser Queue**: localStorage batches actions for bulk sync
- ✓ **Timeout Handling**: 8-second Firestore timeout with fallback
- ✓ **Lazy Loading**: Split live cache only loaded on demand

## Browser Queue

Transaction create, edit, and delete forms are marked with `data-offline-queue`. Balance add and sync actions use the same browser queue through JavaScript.

When a user submits one of these actions:

1. The action is saved to `localStorage`.
2. The UI gives immediate feedback.
3. The browser tries to submit the action to Render.
4. If the request fails or times out, the action stays queued.
5. When the backend responds later, queued actions sync one by one.

Create actions use `client_action_id` as the Firestore transaction document id. Edit and delete actions write to a per-user `client_actions` log. Balance entries use action-specific notes so retries do not repeatedly apply the same balance delta.

Only the latest transaction can be edited or deleted. If the latest transaction is deleted, the transaction immediately before it becomes the new editable/deletable transaction. A latest transaction edit must also keep that transaction latest by date/time. This keeps balance repair math ordered and avoids changing older history while newer balance entries already depend on it. The same rule is enforced in the UI, normal form routes, and JSON APIs, so queued edits/deletes are rejected if they are no longer valid when Render wakes.

If browser storage is unavailable, the app falls back to normal form submission.

## Historical Transactions & Balance Ledger Safety

FinTrak allows full historical CRUD mutations on transactions. Users can edit or delete any transaction regardless of its position in the ledger history.

- **Reversible Audit Trails**: When a historical transaction is updated or deleted, the system automatically computes the absolute monetary delta and appends a corresponding balance ledger adjustment at the current time. This fully preserves the historical chronological balance timeline while correctly aligning the user's current cashflow.
- **Restricted Balance Adjustments**: Unlike transaction records, manual cashflow balance entries (`Add` and `Sync`) are restricted to only the latest manual entry. Older manual adjustments render a disabled "Locked" badge to preserve sequential balance repair integrity.

## Balance Behavior

The Balance page supports manual add and sync actions.

- Add stores a balance delta.
- Sync stores a new absolute balance and calculates the delta from the previous balance.
- Manual add/sync balance entries can be edited from the balance ledger.
- The balance ledger shows the newest 12 balance changes. The browser cache keeps the same 12 entries for Render-asleep/offline fallback.
- Editing a sync entry still means editing its absolute balance. The edit modal previews the recalculated entry delta and the later-balance shift.
- The previous Undo Last control is removed; transaction reversals should happen from the Transactions page by deleting the latest transaction.

Balance add and sync actions use the browser queue. If Render is asleep, the action remains in `localStorage`, appears in Sync Status, and is submitted after `/api/render_status` confirms the service is awake.

## Split Documents & Global Sidebar Drawer

The Splits page stores shared-spend documents such as `Chennai trip`. We have introduced a global navigation drawer allowing you to browse, search, and jump to any split document instantly from any page.

### 🗂️ Global Splits Sidebar Drawer
- **Left-Floating Arrow Toggle**: Stays pinned to the left edge of the screen, expanding and triggering a subtle chevron nudge animation on hover.
- **Glassmorphic Slide Drawer**: Slides in smoothly from the left edge (`-320px` to `0`), utilizing custom backdrop filters to softly blur background elements.
- **Real-Time Search**: Allows instant, character-by-character filtering of your split documents.
- **Render Sleep State Resilience**: If the Render server is sleeping or completely offline, the drawer automatically falls back to loading your previously loaded splits list from `localStorage` (`fintrak_splits_list_cache`), showing the lists cleanly with offline fallback data and preventing broken user experiences.

### ⚙️ Split Document Mechanics
- **Management Setup**: Management page has a Split People table used by split entry person dropdowns.
- **Live Status Streamlining**: All new splits are automatically set to `is_live=True` when created. The main splits listing replaces checkboxes with sleek static badges (`Live` or `Saved`) and renders a clean `Make Live` button in the action menu for saved splits.
- **Only One Active Split**: Only one split can be live at a time; activating a new or saved split automatically clears the live flag from other documents.
- **Bug Fix**: Editing a split document title now fully preserves its current `is_live` status instead of forcing it to `True`.
- **Entries**: Inside each split document, you can add split entries containing amount, person, description, category, date, and time.
- **Split Detail Totals**: Renders per-person total expense cards dynamically summing their entries.
- **Offline Entry Queue**: Fully buffers split entry add, edit, and delete operations inside IndexedDB `offline_queue` during Render sleep states, auto-syncing when the server wakes up.

### View-Only Sessions
- View-only sessions have full read-only access to splits list and summaries but are blocked from any write operations (which return `403` or `401` on direct route hits).
- Controls like New Split, Edit, Delete, and Make Live buttons are hidden.

---

## ⚡ Background Sync & Performance Optimizations

### 💤 Resource-Saving Background Sync Polling
- **Active Polling Suspension**: Re-engineered the background worker in `sync_status.js` so that once the Render service is awake, local caches are fully synced, and the pending actions queue is empty, the client **suspends background status fetch requests completely**. This saves client mobile data and cuts down backend server CPU load to zero.
- **Instant Mutation Auto-Wakeup**: Connected the `'fintrak:queuechange'` event handler to trigger an immediate status check. As soon as the user performs any write mutation (add, edit, delete) in offline or sleeping states, the sync worker instantly wakes up, verifies Render wakefulness, and flushes the queue immediately.

### 🎭 Global Edit Backdrop Blur Overlays
- **Inline Editing Focus**: Injected a fixed backdrop blur overlay and active focused form-card styling to all list pages where editing actions are handled inline on the same page:
  - **Split Bills Page (`splits.html`)**: Active backdrop blur when editing a split title.
  - **Recurring Bills Page (`recurring.html`)**: Active backdrop blur when editing an Expense Rule or Balance Rule.
  - **Setup & Settings Page (`management.html`)**: Active backdrop blur when editing a Transaction Category or Split Person.
- **Elite Motion Styling**: The backdrop features an 8px blur filter, dims the background, and intercepts all background clicks. The active card scales up smoothly to `1.02x` with a primary teal shadow glow.

### 📐 Visual Layout, Table scrolling & Dark-Theme Visibility
- **Fluid Layout Spacing**: Changed `.table-responsive`'s `overflow-x` to `auto` globally, enabling wide tables on laptops and desktops to scroll horizontally rather than aggressively squeezing column cells.
- **Vertical Date Column Wrapping**: Excluded all date/time columns (`When`, `Date`, `Updated`, `Start`, `Last Applied`, `Last Added`) from the strict `nowrap` selector. Date values automatically stack dates and times vertically on compact screens to maintain optimal spacing.
- **Native Browser Component Dark-Theming**: Removed the global `color-scheme: light` override. Native inputs, selector options, calendar date pickers, and scrollbars now automatically render in native high-contrast dark mode when the dark theme is active.
- **Group-By Alignment**: Moved the global Spend Analytics "Group by" selector up into the top row directly alongside the range presets, keeping only custom From and To date inputs below the `(or) Custom Dates` separator.


## Caching

The app uses a small in-process TTL cache for:

- category settings
- split people settings
- view-only password hash status
- full-login user auth documents

The cache reduces repeated Firestore reads during normal page loads and login. Category, view-only password, username, and full-login password updates refresh the relevant cached value immediately. After the app is idle or the system wakes, the next request runs a cache check/update job first so fresh Firestore updates are loaded into cache before normal work continues.

The Sync Status page also asks `/api/render_status` to run one cache check/update job when Render wakes, before pending browser actions are synced. After queued actions sync, the browser cache snapshot refreshes so balance, balance history, categories, recent transactions, split people, and the live split stay current locally.

The login and view-only login pages show service/cache status too. They poll `/api/login_wake_status`, show a waking state while the service is not ready, and run one cache check/update job before login.

Password checks always refresh the user's real Firestore password hash before comparison. If a password hash is already in server cache, the login page can show that cache as available, but the submitted password is still checked against the latest Firestore hash when the service is awake.

Configure the TTL with `CACHE_TTL_SECONDS`. Default: `300`.
Configure the login auth TTL with `AUTH_CACHE_TTL_SECONDS`. Default: `604800` seconds, which is 7 days.
Configure the wake/idle refresh threshold with `WAKE_REFRESH_IDLE_SECONDS`. Default: `300` seconds.

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
- `AUTH_CACHE_TTL_SECONDS`: login auth cache duration. Default: `604800` seconds, which is 7 days.
- `WAKE_REFRESH_IDLE_SECONDS`: run the cache check/update job on the first request after this many idle seconds. Default: `300`.
- `FIRESTORE_TIMEOUT_SECONDS`: timeout for critical Firestore reads used during auth/settings rendering. Default: `8`.
- `ENABLE_DEBUG_ROUTES`: optional recurring diagnostics route switch. Keep unset or `false` in production.
- `LOG_LEVEL`: Flask log level. Default: `INFO`.
- `FLASK_DEBUG`: local debug flag. Keep disabled in production.

## Row Limits

Table/cache preview limits live in `constants.py` and are set to 12:

- `TRANSACTION_PAGE_SIZE`
- `RECENT_TRANSACTIONS_CACHE_LIMIT`
- `BALANCE_HISTORY_TABLE_LIMIT`
- `RECURRING_RULE_TABLE_LIMIT`
- `SPLIT_DOCUMENT_TABLE_LIMIT`
- `SPLIT_ENTRY_TABLE_LIMIT`

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
- Test transaction add, latest-only edit/delete, queue retry, and background sync.
- Test recurring expense rules, recurring balance rules, split documents, split entries, categories, split people, view-only password change, balance actions, analytics, CSV export, dark mode, and mobile layouts.

## Verification

Frontend JavaScript syntax checks:

```bash
node --check static\js\script.js
node --check static\js\offline_queue.js
node --check static\js\sync_status.js
node --check static\js\browser_cache.js
node --check static\js\balance.js
node --check static\js\splits.js
node --check static\js\analytics.js
node --check static\js\flash.js
```

Python syntax check in an environment with Python installed:

```bash
python -B -c "import ast, pathlib; [ast.parse(pathlib.Path(p).read_text(encoding='utf-8'), filename=p) for p in ('app.py','forms.py')]; print('syntax ok')"
```

Recommended module checks:

- Verify latest-only transaction edit/delete, including deleting the newest transaction and confirming the previous one unlocks.
- Verify stale queued transaction edit/delete actions are rejected if they are no longer latest when Render wakes.
- Verify balance add/sync queue while Render is asleep and successful submission after Render wakes.
- Verify recurring expense and recurring balance rule create/edit/delete.
- Verify split document create/edit/delete, live marking, split entry create/edit/delete, and person total boxes.
- Verify only the live split is included in the browser cache and non-live split pages require Render awake.
- Verify Balance edit math for manual add and sync entries.
- Verify mobile tables render as labeled cards and desktop tables keep the standard table layout.

Split module verification commands used during development:

```bash
python -B -m flask --app app routes
python -B -c "from app import app; [app.jinja_env.get_template(t) for t in app.jinja_env.list_templates()]; print('templates ok')"
python -B -c "import app; app.get_split_people=lambda:['Alice','Bob']; app.get_categories=lambda:['Food','Travel','Other']; valid={'person':'Alice','amount':'123.45','description':'Dinner','category':'Food','date':'2026-05-29','time':'20:15'}; doc=app.build_split_entry_doc_from_payload(valid); assert doc['person']=='Alice' and doc['amount']==123.45; print('split validation ok')"
python -B -c "import app; app.get_split_documents=lambda username=None:[{'id':'s1','title':'Chennai trip','is_live':True,'updated_at':None}]; app.get_live_split=lambda username=None:{'id':'s1','title':'Chennai trip','is_live':True}; c=app.app.test_client(); ctx=c.session_transaction(); s=ctx.__enter__(); s['view_only']=True; s['username']='viewer@example.com'; ctx.__exit__(None,None,None); r=c.get('/splits'); html=r.get_data(as_text=True); assert r.status_code==200; assert 'Management' not in html and '>People<' not in html and 'New Split' not in html and 'Edit</a>' not in html and 'Delete</button>' not in html and 'Make Live' not in html; assert c.get('/management').status_code==401; assert c.get('/splits/edit/s1').status_code==401; print('view-only splits ok')"
```

Local smoke check:

```bash
python -B -m flask --app app run --port 5002
```

Then request `http://127.0.0.1:5002/login` and expect HTTP `200`. Stop the temporary server after the check.

## Known Scaling Note

The transaction page uses Firestore cursor pagination instead of `.offset()`. Search is implemented inside the current sorted Firestore stream, so it avoids full collection scans by default. If transaction volume becomes very large and search must cover every historical record, add a dedicated search index such as Algolia, Typesense, Meilisearch, or a normalized Firestore search collection.
