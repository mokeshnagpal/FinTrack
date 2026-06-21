# FinTrak - Ultimate Personal Finance Tracker

FinTrak is a highly interactive, full-stack personal finance web application built using **Flask** and **Google Firestore**. It provides real-time transaction ledger management, running balance histories, multi-currency/split payment calculations, trip expense aggregation, recurring transaction planners, and visual analytics dashboards. 

FinTrak utilizes a secure multi-role access control system (Admin, User, and View-Only), is completely responsive (Bootstrap 5), and features customized interactive tables with client-side sorting and paginated server-side searching.

---

## 📖 Table of Contents
1. [What FinTrak Does (Feature Breakdown)](#-what-fintrak-does-feature-breakdown)
2. [Multi-Role Access Control & Security](#-multi-role-access-control--security)
3. [Architecture & System Modules](#-architecture--system-modules)
4. [Database & Collection Schema Deep-Dive](#-database--collection-schema-deep-dive)
5. [Visibility & Action Matrix (Single Source of Truth)](#-visibility--action-matrix-single-source-of-truth)
6. [Frontend & static Scripts Guide](#-frontend--static-scripts-guide)
7. [Environment Variables Reference](#-environment-variables-reference)
8. [Local Development & Setup Guide](#-local-development--setup-guide)
9. [Repair & Diagnostic Scripts](#-repair--diagnostic-scripts)

---

## 🌟 What FinTrak Does (Feature Breakdown)

### 💵 Transaction Ledger
* **Categorized Entries:** Log details including amounts, tags, descriptions, transaction dates, and custom categories.
* **Saved Transaction Templates:** Save frequent transactions (e.g. rent, groceries) as reusable templates to quickly submit them to the main ledger.
* **Search & Filters:** Search transactions by title, category, or amount via server-side range queries.

### 📈 Balance Tracking & Adjustments
* **Chronological Running Balance:** Keeps a strict, real-time running total of your funds. Every transaction or balance update automatically triggers a chronological recalculation of all subsequent entries.
* **Sync Adjustments:** Allows absolute balance syncing (e.g., syncing FinTrak to your physical bank account's balance). The backend automatically computes the positive/negative delta adjustment and posts it to the ledger.
* **Manual Additions:** Record manual credit or debit events without affecting the general transaction ledger.

### ⏱️ Recurring Scheduler Rules
* **Recurring Transactions:** Define transaction templates that automatically generate at set intervals (daily, weekly, monthly, yearly).
* **Recurring Balances:** Define rules to automatically apply credits or debits directly to your running balance ledger at scheduled intervals.
* **Run Window Control:** Uses an execution throttle configuration (`OCCURRENCE_WINDOW_SECS`) to prevent duplicate scheduling operations.

### 👥 Split Expense Manager
* **Split Groups:** Set up expense splits between participants managed on the admin panel.
* **Weighted Settlements:** Define overall costs and track individual shares.
* **Ledger Syncing:** Changes made within the Split module automatically push corresponding balance ledger rows, complete with a `"View Split"` action for fast cross-navigation.

### ✈️ Trip Tracker
* **Trip Grouping:** Accumulate and record expenses grouped under specific trips (e.g., business travel, vacations).
* **Individual vs Shared:** Set trip costs as individual expenses or integrate them directly with the Split Module to divide them among trip participants.

### 📊 Real-Time Analytics
* **Category Spending Trends:** Interactive pie charts tracking total spending per category using Chart.js.
* **History Trend Lines:** Area charts representing historical balance variations over days, months, or years.

---

## 🔒 Multi-Role Access Control & Security

FinTrak supports three permission roles stored as session flags:

1. **Admin User (`session['is_admin'] = True`)**
   * Full write access to create, edit, or delete transactions, categories, and settings.
   * Can configure the view-only access passwords.
   * Access to category creation/deletion and member lists on the `/management` page.
2. **Normal User**
   * Can read and modify their own transaction records.
   * Cannot delete core categories marked as `protected` or modify restricted admin settings.
3. **View-Only Session (`session['view_only'] = True`)**
   * Granted via a distinct view-only password.
   * Restricts all mutating operations (POST, PUT, DELETE requests are blocked by decorators).
   * Grants read-only access to dashboards, transaction history, splits, and analytics.

### Request De-duplication
To prevent duplicate double-posts (e.g. from rapid double-clicks on submit buttons), the application computes a SHA-256 hash of mutating request payloads and checks them against a session cache. If the same payload is sent twice within `5` seconds, the second request is rejected.

---

## 🏗️ Architecture & System Modules

### Backend Python Modules
* **[app.py](file:///d:/PROJECTS/SELF%20PROJECTS/__TOOLS%20I%20AM%20USING/WEBSITE/Fintrak/app.py):** Main Flask controller containing all route handlers, authentication decorators, Firestore query logic, running balance recalculation code, and AJAX API endpoints.
* **[forms.py](file:///d:/PROJECTS/SELF%20PROJECTS/__TOOLS%20I%20AM%20USING/WEBSITE/Fintrak/forms.py):** Houses all WTForms schemas containing validation constraints, custom error messages, field patterns, and UI configurations.
* **[constants.py](file:///d:/PROJECTS/SELF%20PROJECTS/__TOOLS%20I%20AM%20USING/WEBSITE/Fintrak/constants.py):** Global configurations and defaults.

### Templates Structure (`templates/`)
* **[base.html](file:///d:/PROJECTS/SELF%20PROJECTS/__TOOLS%20I%20AM%20USING/WEBSITE/Fintrak/templates/base.html):** Standard boilerplate layout, dark theme styling elements, global layouts, and Javascript utilities initialization.
* **`macros/ui.html`:** Reusable WTForm field templates, custom styling, and layout widgets.
* **`index.html`:** General user dashboard compiling brief statistics.
* **`transactions.html`:** The transaction list view, filters, search, and template managers.
* **`balance.html`:** The running balance list, balance additions, and sync widgets.
* **`recurring.html`:** Configuration area for transaction and balance recurring schedules.
* **`splits.html` & `split_detail.html`:** Interactive split expense dashboards and participant allocations.
* **`trips.html`:** Trip cataloging and cost structures.
* **`management.html`:** Admin controls, category editing, password changes, and member lists.

---

## 🗄️ Database & Collection Schema Deep-Dive

FinTrak uses Google Firestore to store all data. The data model begins under a top-level collection named `users`, where each username (email) represents a user document.

### Top-Level Collections
```text
users/
└── {username}/              <-- User Document (contains login credentials & categories map)
    ├── transactions/        <-- Subcollection: Transaction list
    ├── balances/            <-- Subcollection: Running balances ledger
    ├── recurring/           <-- Subcollection: Recurring transaction scheduler rules
    ├── recurring_balances/  <-- Subcollection: Recurring balance scheduler rules
    ├── splits/              <-- Subcollection: Splits
    │   └── {split_id}/
    │       └── entries/     <-- Subcollection: Split expense entries
    ├── trips/               <-- Subcollection: Trip entries
    └── saved_transactions/  <-- Subcollection: Saved transaction templates
```

---

### Firestore Document Structure Specifications

#### 1. User Document Path: `users/{username}`
* `password`: Hashed string (bcrypt or pbkdf2) for main user login.
* `view_pass`: Hashed string for view-only session access.
* `admin_pass`: Hashed string for supervisor admin logins (optional).
* `categories`: Map of category names to security classifications:
  ```json
  {
    "Food": "protected",
    "Entertainment": "public",
    "Utilities": "protected"
  }
  ```
* `split_people`: Array of strings denoting available participant names for splits.
* `default_category`: String name of the category pre-selected in forms.

#### 2. Subcollection: `transactions`
* `amount`: Positive float value representing the transaction cost.
* `description`: String (max 120 chars) describing the transaction.
* `category`: String representing the transaction category.
* `timestamp`: UTC Timestamp indicating when the transaction took place.
* `created_at`: UTC Timestamp indicating when the record was created.
* `updated_at`: UTC Timestamp indicating when the record was last modified.
* `cost_type`: String (`"individual"` or `"split"`).
* `split_id`: String ID pointing to a split document (if split-linked).
* `split_title`: String title of the linked split.
* `recurring_id`: String ID of the recurring rule that generated this transaction.

#### 3. Subcollection: `balances`
* `balance`: Float representation of the running balance after this entry.
* `delta`: Float value representing the change (+/-) applied.
* `type`: String type (`"txn"` for transactions, `"balance"` for manual entries, `"sync"` for absolute balance syncs).
* `mode_name`: String mode classification:
  * `"txn-add"`: Created from a normal transaction.
  * `"recurring"`: Created from a recurring rule execution.
  * `"split"`: Created from a split action.
  * `"balance-add"`: Manual balance adjustment.
  * `"balance-sync"`: Delta adjustment from an absolute sync.
* `txn_id` / `transaction_id`: String referencing the source transaction (if `type="txn"`).
* `notes` / `note`: String text detail describing the entry.
* `timestamp`: UTC Timestamp.

#### 4. Subcollection: `splits`
* `title`: String title of the split group.
* `people`: Array of strings (names of participants involved).
* `total_amount`: Float summation of all shared costs.
* `created_at`: UTC Timestamp.
* `updated_at`: UTC Timestamp.

#### 5. Subcollection: `splits/{split_id}/entries`
* `amount`: Float cost of this specific item/entry.
* `description`: String name or description.
* `payer`: String name of the person who paid.
* `weight`: Map of person names to share weight values (e.g. `{"Alice": 1, "Bob": 0}`).
* `date`: String date (`"YYYY-MM-DD"`).

---

## 📊 Visibility & Action Matrix (Single Source of Truth)

To keep transaction lists synchronized with the balance history ledger without double-counting, the app uses a strict action control policy:

| Record Type | Appears in Transaction Table | Appears in Balance History Table | Editable from Transaction History | Editable from Balance History | Deletability | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Normal Transaction** | Yes | Yes (type `txn`, mode `txn-add`) | ✅ Yes | ✅ Yes | ✅ Yes | Deleting/editing from either table automatically syncs or deletes the corresponding record in both collections. |
| **Recurring Generated** | Yes | Yes (type `txn`, mode `recurring`) | ✅ Yes | ✅ Yes | ✅ Yes | Generated automatically but behaves as a normal transaction once instantiated. |
| **Split-Linked Expense** | Yes | Yes (type `txn`, mode `split`) | ❌ No | ❌ No | ❌ No | Action is restricted to `"View Split"`. Modifications must be made via the Split Module, which auto-updates the ledger. |
| **Manual Balance Adjustment** | No | Yes (type `balance`, mode `balance-add`) | ❌ N/A | ✅ Yes | ✅ Yes | Only exists in the Balance History table. |
| **Balance Sync Entry** | No | Yes (type `balance`, mode `balance-sync`) | ❌ N/A | ✅ Yes | ✅ Yes | Only exists in the Balance History table. Represents the delta computed during a sync. |
| **Recurring Balance Adjustment** | No | Yes (type `balance`, mode `recurring`) | ❌ N/A | ✅ Yes | ✅ Yes | Generated by recurring balance rules. |

---

## 🖥️ Frontend & Static Scripts Guide

The frontend logic is written in vanilla Javascript inside [static/js/](file:///d:/PROJECTS/SELF%20PROJECTS/__TOOLS%20I%20AM%20USING/WEBSITE/Fintrak/static/js/):

* **[script.js](file:///d:/PROJECTS/SELF%20PROJECTS/__TOOLS%20I%20AM%20USING/WEBSITE/Fintrak/static/js/script.js):** 
  * Establishes `initUnifiedTable` which handles pagination calculations, client-side dynamic sorting of visible rows, and table formatting.
  * Checks required input form states in real-time, disabling the submit buttons until validation states are resolved.
* **`balance.js` & `splits.js`:** 
  * Controls the dynamic modals, input weight bindings, calculations, and ajax submit requests to their respective routes.
* **`analytics.js` & `balance_analytics.js`:**
  * Connects to endpoint channels to grab formatted JSON payloads and render them into Chart.js elements.

---

## ⚙️ Environment Variables Reference

Create a file named `.env` in the project root containing these variables:

```bash
# Flask Core
FLASK_SECRET="super-secret-cryptographic-hash"
SESSION_LIFETIME_HOURS=12

# Firebase Admin Credential Configuration (Copy exact Service Account JSON text)
FIREBASE_CREDENTIALS='{"type": "service_account", "project_id": "fintrak-prod", ...}'

# User Authentication fallbacks
ADMIN_USER="admin@email.com,manager@email.com"
ADMIN_PASS="defaultAdminPassword123"
VIEW_PASS="optionalViewOnlyToken123"

# Engine Adjustments
OCCURRENCE_WINDOW_SECS=60
FIRESTORE_TIMEOUT_SECONDS=10
FORCE_HTTPS=False
```

---

## 🚀 Local Development & Setup Guide

### 1. Prerequisites
* Python 3.10+ installed.
* A Firebase Project with Firestore enabled.
* A downloaded Firebase Service Account credentials JSON file.

### 2. Installation
Clone the repository and initialize a virtual environment:

```bash
# Setup virtual environment
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Running Locally
Start the Flask development server:

```bash
# Set Flask entrypoint
set FLASK_APP=app.py     # On macOS/Linux: export FLASK_APP=app.py
set FLASK_DEBUG=1        # On macOS/Linux: export FLASK_DEBUG=1

# Start the application
flask run
```

Access the application in your browser at `http://127.0.0.1:5000`.

---

## 🛠️ Repair & Diagnostic Scripts

The repository contains scripts to inspect and repair data inconsistencies:

### `scripts/repair_preview.py`
A CLI tool designed to inspect Firestore balance and transaction data for errors (e.g. incorrect `type` or missing `txn_id` linkages in balance documents) and repair them:
* **Dry-Run Mode (Default):** Runs an diagnostic scan of all user collections and prints a table of changes it would make without writing to Firestore.
* **Execution Mode:** To execute changes, run the script with `ALLOW_FIRESTORE_WRITES=1` and pass the `--apply` flag.
* Has built-in safety boundaries (limits firestore operations to `50,000` combined calls to protect database quotas).
