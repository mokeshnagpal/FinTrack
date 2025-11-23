from flask import (
    Flask, render_template, redirect, url_for, flash,
    request, jsonify, send_file, abort, session
)
from functools import wraps

from datetime import datetime, date, time as dt_time, timezone, timedelta
from dateutil.relativedelta import relativedelta
from forms import TransactionForm, RecurringForm, LoginForm
import os
import io
import csv
import statistics
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import credentials, firestore
from types import SimpleNamespace
import logging
import json
from urllib.parse import urlparse, urljoin


# ----------------------------
# Configuration
# ----------------------------
UTC = timezone.utc
# widen occurrence window from ±1s to ±60s to avoid precision/tz mismatch (tweak as needed)
OCCURRENCE_WINDOW_SECS = int(os.environ.get('OCCURRENCE_WINDOW_SECS', '60'))

# load env
load_dotenv()


# ---------------------------------------------------------------------
# Firebase / Firestore init
# ---------------------------------------------------------------------
firebase_credentials_str = os.environ.get('FIREBASE_CREDENTIALS')
if not firebase_credentials_str:
    raise ValueError("FIREBASE_CREDENTIALS environment variable not set.")

firebase_credentials_dict = json.loads(firebase_credentials_str)

# Replace literal '\\n' with actual newline characters in the private key
if 'private_key' in firebase_credentials_dict:
    firebase_credentials_dict['private_key'] = firebase_credentials_dict['private_key'].replace('\\n', '\n')

# Initialize Firebase Admin with the credentials dictionary
cred = credentials.Certificate(firebase_credentials_dict)

# avoid double-initialize in dev reloader
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)

fs = firestore.client()

# collection names (kept for backwards reference but we now use per-user subcollections)
TX_COL = "transactions"
REC_COL = "recurring"
BAL_COL = "balances"

# ---------------------------------------------------------------------
# Flask App Configuration
# ---------------------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET')
app.config['SQLALCHEMY_DATABASE_URI'] = 'firestore://'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_REFRESH_EACH_REQUEST'] = False

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=bool(os.environ.get('FORCE_HTTPS', False)),
    SESSION_COOKIE_SAMESITE='Lax',
)
# keep sessions effectively permanent until logout (adjust as needed)
app.permanent_session_lifetime = timedelta(days=3650)  # ~10 years

# configure logging
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
app.logger.setLevel(logging.DEBUG)
app.logger.addHandler(handler)

# ---------------------------------------------------------------------
# Utilities: timestamp parsing & document conversion
# ---------------------------------------------------------------------
# --- simple session-based auth helpers ---
# read ADMIN_USER (comma separated emails/usernames) and ADMIN_PASS from env
ADMIN_USER_RAW = os.environ.get('ADMIN_USER', '')
# parse -> lowercase set
ADMIN_USERS = set(u.strip().lower() for u in ADMIN_USER_RAW.split(',') if u.strip())
ADMIN_PASS = os.environ.get('ADMIN_PASS', 'password')  # change in prod!

# ---------- user-scoping helpers ----------
def is_valid_user(username):
    """
    Return True if username is allowed:
     - present in ADMIN_USERS env list OR
     - a document exists at users/{username} in Firestore
    Username is normalized to lowercase before checks.
    """
    if not username:
        return False

    uname = str(username).strip().lower()

    # quick env-list check
    if uname in ADMIN_USERS:
        return True

    # fallback: check Firestore users collection (exists -> allowed)
    try:
        doc = fs.collection('users').document(uname).get()
        return doc.exists
    except Exception:
        app.logger.exception("is_valid_user: Firestore check failed for %s", uname)
        return False

def get_current_username():
    """Return the logged-in username or None."""
    return session.get('username')

def require_user():
    """Return username or abort 401 (used in API code paths)."""
    u = get_current_username()
    if not u:
        abort(401, description="Authentication required")
    return u

def user_doc_ref(username=None):
    """
    Return DocumentReference to users/{username}.
    If username is None, uses the logged-in user (and aborts if not logged in).
    """
    if username is None:
        username = require_user()
    return fs.collection('users').document(str(username))

def tx_collection(username=None):
    """CollectionReference for users/{username}/transactions"""
    return user_doc_ref(username).collection('transactions')

def rec_collection(username=None):
    """CollectionReference for users/{username}/recurring"""
    return user_doc_ref(username).collection('recurring')

def bal_collection(username=None):
    """CollectionReference for users/{username}/balances"""
    return user_doc_ref(username).collection('balances')


def is_safe_redirect_url(target):
    host_url = request.host_url
    ref = urljoin(host_url, target)
    return urlparse(ref).netloc == urlparse(host_url).netloc


def login_required(view_fn):
    @wraps(view_fn)
    def wrapped(*args, **kwargs):
        # allow REST APIs and static files to be called without login
        # adjust this list as you need (e.g. public endpoints)
        if session.get('logged_in'):
            return view_fn(*args, **kwargs)
        # allow health/static/login/api endpoints to run without auth
        path = request.path or ''
        allowed_prefixes = ['/static/', '/export/', '/debug/recurring_run', '/login']
        if any(path.startswith(p) for p in allowed_prefixes):
            return view_fn(*args, **kwargs)
        # otherwise redirect to login page
        return redirect(url_for('login', next=request.path))
    return wrapped


def ts_to_dt(ts):
    """
    Convert Firestore Timestamp / datetime / ISO-string to timezone-aware UTC datetime.
    """
    if ts is None:
        return None

    # Firestore may return a native datetime
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=UTC)
        return ts.astimezone(UTC)

    # fallback: try parsing ISO string
    try:
        dt = datetime.fromisoformat(str(ts))
        if dt.tzinfo is None:
            return dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except Exception as e:
        raise ValueError(f"Unsupported timestamp format: {type(ts)} ({e})")

def doc_to_txn(doc):
    """
    Convert DocumentSnapshot or dict to plain dict, normalize datetime fields and ensure id/_id exist.
    """
    if hasattr(doc, 'to_dict'):
        d = doc.to_dict() or {}
    elif isinstance(doc, dict):
        d = dict(doc)
    else:
        d = dict(doc)

    # expose doc id under both keys for templates
    if hasattr(doc, 'id'):
        d['_id'] = doc.id
        d['id'] = doc.id
    elif '_id' in d and 'id' not in d:
        d['id'] = d['_id']
    elif 'id' in d and '_id' not in d:
        d['_id'] = d['id']

    # normalize datetime fields used by the app
    for fld in ('timestamp', 'start_datetime', 'last_applied'):
        if fld in d and d[fld] is not None:
            try:
                d[fld] = ts_to_dt(d[fld])
            except Exception:
                # leave as-is if conversion fails
                pass

    return d

# ---------------------------------------------------------------------
# Firestore helpers
# ---------------------------------------------------------------------
def get_txns_in_range(start_dt, end_dt, order_desc=True, username=None):
    """
    If username is None, uses the logged-in user. Returns list of txn dicts.
    """
    if start_dt.tzinfo is None:
        start_dt = start_dt.replace(tzinfo=UTC)
    if end_dt.tzinfo is None:
        end_dt = end_dt.replace(tzinfo=UTC)

    if username is None:
        username = require_user()

    coll = tx_collection(username)
    q = coll.where('timestamp', '>=', start_dt).where('timestamp', '<=', end_dt)
    if order_desc:
        q = q.order_by('timestamp', direction=firestore.Query.DESCENDING)
    else:
        q = q.order_by('timestamp', direction=firestore.Query.ASCENDING)
    docs = q.stream()
    return [doc_to_txn(doc) for doc in docs]


def get_recurring_active(username=None):
    if username is None:
        username = require_user()
    docs = rec_collection(username).where('active', '==', True).stream()
    return [doc_to_txn(doc) for doc in docs]

# ---------------------------------------------------------------------
# Recurring runner (idempotent)
# ---------------------------------------------------------------------
def occurrence_exists(recurring_doc_id, occ_dt, window_secs=OCCURRENCE_WINDOW_SECS, username=None):
    if occ_dt is None:
        return False
    if occ_dt.tzinfo is None:
        occ_dt = occ_dt.replace(tzinfo=UTC)
    if username is None:
        username = require_user()

    window_start = occ_dt - timedelta(seconds=window_secs)
    window_end = occ_dt + timedelta(seconds=window_secs)

    rec_str = str(recurring_doc_id)
    q = (tx_collection(username)
         .where('recurring_id', '==', rec_str)
         .where('timestamp', '>=', window_start)
         .where('timestamp', '<=', window_end)
         .limit(1))
    try:
        docs = list(q.stream())
        return len(docs) > 0
    except Exception as e:
        app.logger.exception("occurrence_exists query failed for %s at %s: %s", recurring_doc_id, occ_dt, e)
        return False


def create_txn_and_mark(rec_ref, rec_id, next_occ, txn_doc, username=None):
    """
    Attempt to create a transaction doc and update recurring.last_applied in a transaction.
    This reduces race conditions. If transactional write fails, it will raise.
    """
    if username is None:
        username = require_user()

    transaction = fs.transaction()

    def txn_op(tx):
        # re-check existence inside txn
        window_start = next_occ - timedelta(seconds=OCCURRENCE_WINDOW_SECS)
        window_end = next_occ + timedelta(seconds=OCCURRENCE_WINDOW_SECS)

        q = (tx_collection(username)
             .where('recurring_id', '==', str(rec_id))
             .where('timestamp', '>=', window_start)
             .where('timestamp', '<=', window_end)
             .limit(1))

        found = len(list(q.stream()))
        if found > 0:
            # nothing to do
            return

        # create txn doc with generated id in user's transactions subcollection
        new_txn_ref = tx_collection(username).document()  # generate id
        tx_doc = dict(txn_doc)
        # ensure timestamp is a timezone-aware datetime; Firestore will store as timestamp
        ts = tx_doc.get('timestamp')
        if isinstance(ts, datetime) and ts.tzinfo is not None:
            pass

        # create txn and update recurring doc
        tx.set(new_txn_ref, tx_doc)
        tx.update(rec_ref, {'last_applied': next_occ})

    # Run the transaction
    transaction.call(txn_op)


def apply_recurring_up_to_today():
    """
    For each active recurring rule:
      - determine next missing occurrence(s)
      - for each occurrence <= now: if no transaction exists for that occurrence, create it and update last_applied
    Idempotent: repeated runs won't create duplicates.
    """
    # don't attempt to run for anonymous requests
    if not session.get('logged_in'):
        return

    username = require_user()
    now = datetime.now(UTC) + timedelta(hours=5, minutes=30)
    recs = get_recurring_active(username=username) or []
    app.logger.debug("apply_recurring_up_to_today: %d active recurring rules for user %s", len(recs), username)

    for r in recs:
        rec_id = r.get('_id') or r.get('id')
        if not rec_id:
            app.logger.warning("Recurring rule without id: %s", r)
            continue

        # parse datetimes defensively
        try:
            start_dt = ts_to_dt(r.get('start_datetime')) if r.get('start_datetime') else now
        except Exception as e:
            app.logger.exception("Failed parsing start_datetime for %s: %s", rec_id, e)
            start_dt = now

        try:
            last_applied = ts_to_dt(r.get('last_applied')) if r.get('last_applied') else None
        except Exception as e:
            app.logger.exception("Failed parsing last_applied for %s: %s", rec_id, e)
            last_applied = None

        frequency = (r.get('frequency') or 'monthly').lower()
        app.logger.debug("Recurring %s: start=%s last_applied=%s freq=%s",
                          rec_id, start_dt, last_applied, frequency)

        # compute first next occurrence
        if last_applied is None:
            next_occ = start_dt
        else:
            if frequency == 'monthly':
                next_occ = last_applied + relativedelta(months=1)
            elif frequency == 'yearly':
                next_occ = last_applied + relativedelta(years=1)
            else:
                next_occ = last_applied + relativedelta(months=1)

        # If first occurrence is still in future, skip (unless last_applied is None and start <= now)
        if last_applied is None and next_occ > now:
            app.logger.debug("Recurring %s next_occ (%s) in future, skipping, current (%s)", rec_id, next_occ, now)
            continue

        rec_ref = rec_collection(username).document(rec_id)


        # iterate until we're caught up to 'now'
        # limit iterations to avoid accidental infinite loops (safety)
        safety_counter = 0
        while next_occ <= now and safety_counter < 1000:
            safety_counter += 1
            if next_occ.tzinfo is None:
                next_occ = next_occ.replace(tzinfo=UTC)

            try:
                exists = occurrence_exists(rec_id, next_occ, username=username)
            except Exception as e:
                app.logger.exception("Error checking occurrence_exists for %s at %s: %s", rec_id, next_occ, e)
                # break to avoid tight loop on persistent failure
                break

            if exists:
                app.logger.debug("Occurrence already exists for recurring %s at %s", rec_id, next_occ)
                # still update last_applied to advance schedule (this mirrors your original behavior)
                try:
                    rec_ref.update({'last_applied': next_occ})
                except Exception as e:
                    app.logger.exception("Failed to update last_applied for recurring %s: %s", rec_id, e)
            else:
                txn_doc = {
                    'amount': float(r.get('amount', 0.0)),
                    'description': (r.get('description') or '').strip(),
                    'category': r.get('category') or 'Uncategorized',
                    'timestamp': next_occ,
                    'recurring_id': str(rec_id)
                }
                # Try transactional create + mark; fallback to non-transactional if transaction fails
                try:
                    # Build rec_ref again as DocumentReference
                    rec_ref = rec_collection(username).document(rec_id)

                    # Use a transaction to create txn and update last_applied
                    transaction = fs.transaction()

                    def trans_op(tx):
                        # check if occurrence exists inside transaction (per-user collection)
                        window_start = next_occ - timedelta(seconds=OCCURRENCE_WINDOW_SECS)
                        window_end = next_occ + timedelta(seconds=OCCURRENCE_WINDOW_SECS)
                        q = (tx_collection(username)
                             .where('recurring_id', '==', str(rec_id))
                             .where('timestamp', '>=', window_start)
                             .where('timestamp', '<=', window_end)
                             .limit(1))
                        if len(list(q.stream())) > 0:
                            return
                        new_txn_ref = tx_collection(username).document()
                        tx.set(new_txn_ref, txn_doc)
                        tx.update(rec_ref, {'last_applied': next_occ})

                    transaction.call(trans_op)
                    app.logger.info("Created transaction (txn + last_applied updated) for recurring %s at %s (user=%s)", rec_id, next_occ, username)
                    # record balance deduction for the recurring transaction
                    try:
                        append_balance(-float(txn_doc.get('amount', 0.0)), 'recurring', note=f"recurring:{rec_id}", username=username)
                    except Exception:
                        app.logger.exception("Failed to append balance for recurring %s at %s (user=%s)", rec_id, next_occ, username)


                except Exception as e_tx:
                    # transaction failed — try a simple add + update, with robust logging
                    app.logger.exception("Transaction write failed for recurring %s at %s: %s — falling back to add() (user=%s)", rec_id, next_occ, e_tx, username)
                    try:
                        tx_collection(username).add(txn_doc)
                        app.logger.info("Created transaction (fallback add) for recurring %s at %s (user=%s)", rec_id, next_occ, username)
                        # record balance deduction for the fallback-created transaction
                        try:
                            append_balance(-float(txn_doc.get('amount', 0.0)), 'recurring', note=f"recurring:{rec_id}", username=username)
                        except Exception:
                            app.logger.exception("Failed to append balance (fallback) for recurring %s at %s (user=%s)", rec_id, next_occ, username)

                        try:
                            rec_ref.update({'last_applied': next_occ})
                        except Exception as e2:
                            app.logger.exception("Fallback: failed to update last_applied for recurring %s: %s", rec_id, e2)
                    except Exception as e_add:
                        app.logger.exception("Fallback add failed for recurring %s at %s: %s", rec_id, next_occ, e_add)
                        # If a write fails we skip advancing this recurring so we'll retry next run
                        break

            # advance to next occurrence
            if frequency == 'monthly':
                next_occ = next_occ + relativedelta(months=1)
            elif frequency == 'yearly':
                next_occ = next_occ + relativedelta(years=1)
            else:
                next_occ = next_occ + relativedelta(months=1)

        if safety_counter >= 1000:
            app.logger.error("Safety break triggered for recurring %s after %d iterations", rec_id, safety_counter)

# Run before every request
@app.before_request
def ensure_recurring_applied():
    # Only run per-user recurring application for authenticated users
    if not session.get('logged_in'):
        return
    try:
        apply_recurring_up_to_today()
    except Exception:
        app.logger.exception("Error applying recurring rules")

# ---------------------------------------------------------------------
# Debug route (diagnostic)
# ---------------------------------------------------------------------
@app.route('/debug/recurring_run')
def debug_recurring_run():
    username = require_user()
    try:
        recs = get_recurring_active(username=username)
    except Exception as e:
        return jsonify({"error": "Failed to fetch recurring rules", "exc": str(e)}), 500

    now = datetime.now(UTC)
    diagnostics = []

    for r in recs:
        rec_id = r.get('_id') or r.get('id')
        start_dt = None
        last_applied = None
        try:
            start_dt = ts_to_dt(r.get('start_datetime')) if r.get('start_datetime') else None
        except Exception as e:
            start_dt = f"PARSE_ERROR: {e}"
        try:
            last_applied = ts_to_dt(r.get('last_applied')) if r.get('last_applied') else None
        except Exception as e:
            last_applied = f"PARSE_ERROR: {e}"

        frequency = (r.get('frequency') or 'monthly').lower()
        # compute next_occ as your runner does (best effort)
        if isinstance(last_applied, datetime):
            if frequency == 'monthly':
                next_occ = last_applied + relativedelta(months=1)
            elif frequency == 'yearly':
                next_occ = last_applied + relativedelta(years=1)
            else:
                next_occ = last_applied + relativedelta(months=1)
        else:
            next_occ = start_dt or now

        occ_exists = None
        occ_err = None
        if isinstance(next_occ, datetime) and rec_id:
            try:
                occ_exists = occurrence_exists(rec_id, next_occ, username=username)
            except Exception as e:
                occ_exists = False
                occ_err = str(e)

        diagnostics.append({
            "rec_id": rec_id,
            "start_datetime": str(start_dt),
            "last_applied": str(last_applied),
            "frequency": frequency,
            "next_occurrence": str(next_occ),
            "next_occurrence_le_now": isinstance(next_occ, datetime) and next_occ <= now,
            "occurrence_exists": occ_exists,
            "occurrence_check_error": occ_err,
            # don't dump huge raw doc objects in production; here it's useful for debugging
            "raw_doc": r
        })

    run_exc = None
    try:
        apply_recurring_up_to_today()
    except Exception as e:
        run_exc = str(e)
        app.logger.exception("Error during apply_recurring_up_to_today invoked from debug route")

    return jsonify({"now": now.isoformat(), "diagnostics": diagnostics, "runner_exception": run_exc})

# ---------------------------------------------------------------------
# Routes: Pages (unchanged except ensuring timezone-awareness on input)
# ---------------------------------------------------------------------
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    form = TransactionForm()
    if form.validate_on_submit():
        if hasattr(form, 'date') and hasattr(form, 'time'):
            sd = form.date.data or date.today()
            st = form.time.data or datetime.now().time()
            combined_datetime = datetime.combine(sd, st).replace(tzinfo=UTC)
        else:
            combined_datetime = datetime.now(UTC)

        txn_doc = {
            'amount': round(float(form.amount.data), 2),
            'description': form.description.data.strip(),
            'category': form.category.data or 'Uncategorized',
            'timestamp': combined_datetime
        }
        try:
            username = require_user()
            doc_ref, _ = tx_collection(username).add(txn_doc)
            append_balance(-float(txn_doc['amount']), 'txn', note=f"txn:{getattr(doc_ref, 'id', '')}", username=username)
            flash('Transaction added successfully.', 'success')
        except Exception as e:
            app.logger.exception("Failed to add transaction: %s", e)
            flash('Failed to add transaction.', 'warning')

        return redirect(url_for('transactions'))
    return render_template('add.html', form=form)

@app.route('/transactions')
@login_required
def transactions():
    page = int(request.args.get('page', 1))
    per = 5  # show only 5 transactions per page

    # Query Firestore: newest first (per-user)
    username = require_user()
    q = (tx_collection(username)
           .order_by('timestamp', direction=firestore.Query.DESCENDING)
           .limit(per)
           .offset((page - 1) * per))
    docs = q.stream()
    txns_list = [doc_to_txn(doc) for doc in docs]

    # Detect next and previous pages
    has_next = len(txns_list) == per
    has_prev = page > 1

    # Create pagination object
    paginate_obj = SimpleNamespace(
        items=txns_list,
        page=page,
        per_page=per,
        has_next=has_next,
        has_prev=has_prev,
        next_num=page + 1 if has_next else None,
        prev_num=page - 1 if has_prev else None
    )

    return render_template('transactions.html', txns=paginate_obj)


@app.route('/delete/<string:tx_id>', methods=['POST'])
@login_required
def delete(tx_id):
    # fetch the transaction first so we know the amount
    username = require_user()
    doc_ref = tx_collection(username).document(tx_id)
    doc = doc_ref.get()
    if not doc.exists:
        flash('Transaction not found.', 'warning')
        return redirect(url_for('transactions'))

    try:
        txn = doc_to_txn(doc)
        amt = float(txn.get('amount', 0.0))
        # delete transaction
        doc_ref.delete()
        # add back the amount to balances (refund)
        append_balance(float(amt), 'txn_delete', note=f"del_txn:{tx_id}", username=username)
        flash('Transaction deleted.', 'info')
    except Exception as e:
        app.logger.exception("Failed to delete transaction %s: %s", tx_id, e)
        flash('Failed to delete transaction.', 'warning')

    return redirect(url_for('transactions'))

# ---------------------------------------------------------------------
# Routes: Recurring Rules
# ---------------------------------------------------------------------
@app.route('/recurring', methods=['GET', 'POST'])
@login_required
def recurring():
    form = RecurringForm()
    if form.validate_on_submit():
        sd = form.start_date.data
        st = form.start_time.data
        # ensure tz-aware
        start_dt = datetime.combine(sd, st).replace(tzinfo=UTC)

        r_doc = {
            'amount': round(float(form.amount.data), 2),
            'description': form.description.data.strip(),
            'category': form.category.data or 'Uncategorized',
            'start_datetime': start_dt,
            'frequency': form.frequency.data,
            'last_applied': None,
            'active': True
        }
        username = require_user()
        rec_collection(username).add(r_doc)

        flash('Recurring rule saved.', 'success')
        return redirect(url_for('recurring'))

    username = require_user()
    recs = [doc_to_txn(doc) for doc in rec_collection(username).order_by('start_datetime', direction=firestore.Query.DESCENDING).stream()]
    return render_template('recurring.html', form=form, recs=recs)

@app.route('/recurring/delete/<string:r_id>', methods=['POST'])
@login_required
def recurring_delete(r_id):
    username = require_user()
    rec_collection(username).document(r_id).delete()
    flash('Recurring rule deleted.', 'info')
    return redirect(url_for('recurring'))

@app.route('/analytics')
@login_required
def analytics():
    return render_template('analytics.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    # If user already logged in, go to index
    if session.get('logged_in'):
        return redirect(url_for('index'))

    if form.validate_on_submit():
        # normalize username to lowercase for comparisons and storage
        username = (form.username.data or '').strip().lower()
        password = (form.password.data or '').strip()

        # Accept if username appears in ADMIN_USERS or exists in users collection,
        # and supplied password matches ADMIN_PASS.
        if is_valid_user(username) and password == ADMIN_PASS:
            session['logged_in'] = True
            session.permanent = True
            session['username'] = username
            flash('Logged in successfully.', 'success')
            next_url = request.args.get('next') or url_for('index')
            if not is_safe_redirect_url(next_url):
                next_url = url_for('index')
            return redirect(next_url)
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ---------------------------------------------------------------------
# API helpers & endpoints (unchanged)
# ---------------------------------------------------------------------
def _parse_period_args(args):
    period = args.get('period', 'daily')
    count = max(int(args.get('count', 30)), 1)
    # keep "now" in UTC
    now = datetime.now(UTC)

    if period == 'daily':
        end = now
        start = end - relativedelta(days=(count - 1))
        return datetime.combine(start.date(), datetime.min.time()).replace(tzinfo=UTC), \
               datetime.combine(end.date(), datetime.max.time()).replace(tzinfo=UTC), 'daily'

    if period == 'monthly':
        end = now
        first_of_current = date(end.year, end.month, 1)
        start_month = first_of_current - relativedelta(months=(count - 1))
        start = datetime.combine(start_month, datetime.min.time()).replace(tzinfo=UTC)
        last_day = first_of_current + relativedelta(months=1) - relativedelta(days=1)
        end_dt = datetime.combine(last_day, datetime.max.time()).replace(tzinfo=UTC)
        return start, end_dt, 'monthly'

    if period == 'yearly':
        end = now
        start_year = date(end.year - (count - 1), 1, 1)
        start_dt = datetime.combine(start_year, datetime.min.time()).replace(tzinfo=UTC)
        end_dt = datetime.combine(date(end.year, 12, 31), datetime.max.time()).replace(tzinfo=UTC)
        return start_dt, end_dt, 'yearly'

    end = now
    start = end - relativedelta(days=29)
    return datetime.combine(start.date(), datetime.min.time()).replace(tzinfo=UTC), \
           datetime.combine(end.date(), datetime.max.time()).replace(tzinfo=UTC), 'daily'

@app.route('/api/totals')
def api_totals():
    start_dt, end_dt, period = _parse_period_args(request.args)
    labels, values = [], []

    txns = get_txns_in_range(start_dt, end_dt, order_desc=False)

    if period == 'daily':
        cur_date = start_dt.date()
        endd = end_dt.date()
        num_days = (endd - cur_date).days + 1
        results = { (start_dt.date() + relativedelta(days=i)).isoformat(): 0.0 for i in range(num_days) }
        for t in txns:
            d = t['timestamp'].date().isoformat()
            results[d] = results.get(d, 0.0) + float(t.get('amount', 0.0))
        labels = list(results.keys())
        values = [round(results[k], 2) for k in results.keys()]

    elif period == 'monthly':
        cur = date(start_dt.year, start_dt.month, 1)
        endm = date(end_dt.year, end_dt.month, 1)
        months = []
        while cur <= endm:
            months.append(cur)
            cur += relativedelta(months=1)
        labels = [m.strftime('%Y-%m') for m in months]
        month_sums = {m.strftime('%Y-%m'): 0.0 for m in months}
        for t in txns:
            key = t['timestamp'].strftime('%Y-%m')
            if key in month_sums:
                month_sums[key] += float(t.get('amount', 0.0))
        values = [round(month_sums[k], 2) for k in labels]

    elif period == 'yearly':
        years = range(start_dt.year, end_dt.year + 1)
        labels = [str(y) for y in years]
        year_sums = {str(y): 0.0 for y in years}
        for t in txns:
            y = t['timestamp'].year
            if str(y) in year_sums:
                year_sums[str(y)] += float(t.get('amount', 0.0))
        values = [round(year_sums[k], 2) for k in labels]

    amounts = [float(t.get('amount', 0.0)) for t in txns]
    total = round(sum(amounts), 2)
    count = len(amounts)
    avg = round((sum(amounts) / count), 2) if count > 0 else 0.0
    min_amt = round(min(amounts), 2) if count > 0 else 0.0
    max_amt = round(max(amounts), 2) if count > 0 else 0.0
    median = round(statistics.median(amounts), 2) if count > 0 else 0.0

    period_duration = end_dt - start_dt
    prev_end = start_dt - relativedelta(seconds=1)
    prev_start = prev_end - period_duration
    prev_txns = get_txns_in_range(prev_start, prev_end, order_desc=False)
    prev_total = round(sum([float(t.get('amount', 0.0)) for t in prev_txns]), 2)
    pct_change = None
    if prev_total != 0:
        pct_change = round(((total - prev_total) / abs(prev_total)) * 100.0, 2)

    cat_sums = {}
    for t in txns:
        c = t.get('category') or 'Uncategorized'
        cat_sums[c] = cat_sums.get(c, 0.0) + float(t.get('amount', 0.0))
    top_category = {"category": None, "amount": 0.0}
    if cat_sums:
        top = max(cat_sums.items(), key=lambda kv: kv[1])
        top_category = {"category": top[0], "amount": round(top[1], 2)}

    largest_txn = None
    if txns:
        largest = max(txns, key=lambda x: float(x.get('amount', 0.0)))
        largest_txn = {
            "id": largest.get('_id'),
            "amount": round(float(largest.get('amount', 0.0)), 2),
            "description": largest.get('description'),
            "timestamp": largest.get('timestamp').strftime('%Y-%m-%d %H:%M:%S')
        }

    summary = {
        "total": total,
        "count": count,
        "avg": avg,
        "min": min_amt,
        "max": max_amt,
        "median": median,
        "prev_total": prev_total,
        "pct_change": pct_change,
        "top_category": top_category,
        "largest_transaction": largest_txn
    }

    return jsonify({"labels": labels, "values": values, "summary": summary})

@app.route('/api/category_breakdown')
def api_category_breakdown():
    start_dt, end_dt, _ = _parse_period_args(request.args)
    txns = get_txns_in_range(start_dt, end_dt, order_desc=False)
    cat_sums = {}
    for t in txns:
        c = t.get('category') or 'Uncategorized'
        cat_sums[c] = cat_sums.get(c, 0.0) + float(t.get('amount', 0.0))
    data = [{"category": k, "amount": round(v, 2)} for k, v in cat_sums.items()]
    data.sort(key=lambda x: x['amount'], reverse=True)
    return jsonify(data)

@app.route('/api/transactions_range')
def api_transactions_range():
    start_dt, end_dt, _ = _parse_period_args(request.args)
    txns = get_txns_in_range(start_dt, end_dt, order_desc=True)
    out = [{
        "id": t.get('_id'),
        "timestamp": t.get('timestamp').strftime('%Y-%m-%d %H:%M:%S'),
        "description": t.get('description'),
        "category": t.get('category') or 'Uncategorized',
        "amount": round(float(t.get('amount', 0.0)), 2)
    } for t in txns]
    return jsonify({"transactions": out})

@app.route('/export/transactions_csv')
def export_transactions_csv():
    start_dt, end_dt, _ = _parse_period_args(request.args)
    txns = get_txns_in_range(start_dt, end_dt, order_desc=False)

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['id', 'timestamp', 'description', 'category', 'amount'])
    for t in txns:
        cw.writerow([
            t.get('_id'),
            t.get('timestamp').strftime('%Y-%m-%d %H:%M:%S'),
            t.get('description'),
            t.get('category') or '',
            f"{float(t.get('amount', 0.0)):.2f}"
        ])

    buf = io.BytesIO(si.getvalue().encode('utf-8'))
    buf.seek(0)
    filename = f"transactions_{start_dt.strftime('%Y%m%d')}_{end_dt.strftime('%Y%m%d')}.csv"
    return send_file(buf, mimetype='text/csv', as_attachment=True, download_name=filename)

# legacy endpoints (kept for compatibility)
@app.route('/api/daily_totals')
def api_daily_totals():
    end = date.today()
    start = end - relativedelta(days=29)
    start_dt = datetime.combine(start, datetime.min.time()).replace(tzinfo=UTC)
    end_dt = datetime.combine(end, datetime.max.time()).replace(tzinfo=UTC)
    results = {d.isoformat(): 0.0 for d in [start + relativedelta(days=i) for i in range(30)]}
    txns = get_txns_in_range(start_dt, end_dt, order_desc=False)
    for t in txns:
        d = t['timestamp'].date().isoformat()
        results[d] = results.get(d, 0.0) + float(t.get('amount', 0.0))
    labels, values = list(results.keys()), [round(results[k], 2) for k in results.keys()]
    return jsonify({"labels": labels, "values": values})

@app.route('/api/monthly_totals')
def api_monthly_totals():
    end = date.today()
    months = [end - relativedelta(months=i) for i in range(11, -1, -1)]
    labels = [m.strftime('%Y-%m') for m in months]
    totals = []
    for m in months:
        startm = datetime.combine(date(m.year, m.month, 1), datetime.min.time()).replace(tzinfo=UTC)
        endm_date = date(m.year, m.month, 1) + relativedelta(months=1) - relativedelta(days=1)
        endm = datetime.combine(endm_date, datetime.max.time()).replace(tzinfo=UTC)
        txns = get_txns_in_range(startm, endm, order_desc=False)
        s = sum([float(t.get('amount', 0.0)) for t in txns])
        totals.append(round(float(s or 0.0), 2))
    return jsonify({"labels": labels, "values": totals})

# ---------------------------------------------------------------------
# Balance helpers & APIs (new)
# ---------------------------------------------------------------------
def get_balances_in_range(start_dt, end_dt, order_desc=False, username=None):
    if start_dt.tzinfo is None:
        start_dt = start_dt.replace(tzinfo=UTC)
    if end_dt.tzinfo is None:
        end_dt = end_dt.replace(tzinfo=UTC)
    if username is None:
        username = require_user()

    q = (bal_collection(username)
         .where('timestamp', '>=', start_dt)
         .where('timestamp', '<=', end_dt))
    if order_desc:
        q = q.order_by('timestamp', direction=firestore.Query.DESCENDING)
    else:
        q = q.order_by('timestamp', direction=firestore.Query.ASCENDING)
    docs = q.stream()
    return [doc_to_txn(doc) for doc in docs]


def get_latest_balance(username=None):
    if username is None:
        username = require_user()
    q = bal_collection(username).order_by('timestamp', direction=firestore.Query.DESCENDING).limit(1)
    docs = list(q.stream())
    if not docs:
        return None
    return doc_to_txn(docs[0])


def append_balance(delta, type_, note='', username=None):
    if username is None:
        username = require_user()
    try:
        latest = get_latest_balance(username=username)
        base = float(latest.get('balance', 0.0)) if latest else 0.0
    except Exception:
        base = 0.0
    try:
        new_bal = round(base + float(delta), 2)
    except Exception:
        new_bal = round(base + 0.0, 2)

    doc = {
        'balance': float(new_bal),
        'type': str(type_),
        'delta': float(round(float(delta), 2)),
        'note': (note or '')[:1024],
        'timestamp': datetime.now(UTC)
    }
    try:
        add_res = bal_collection(username).add(doc)
        if isinstance(add_res, tuple) and len(add_res) >= 1:
            ref = add_res[0]
            doc_id = getattr(ref, 'id', None)
        else:
            ref = add_res
            doc_id = getattr(ref, 'id', None)
        app.logger.debug("append_balance created %s -> %s (doc id: %s) for user %s", delta, new_bal, doc_id, username)
        return doc_id, doc
    except Exception as e:
        app.logger.exception("Failed to append balance doc for user %s: %s", username, e)
        return None, doc


@app.route('/balance')
@login_required
def balance():
    """Render balance page"""
    return render_template('balance.html')

@app.route('/api/balance_current')
@login_required
def api_balance_current():
    """Return the current/latest balance and a short recent history"""
    username = require_user()
    latest = get_latest_balance(username=username)
    # send back last 20 entries (per-user)
    q = bal_collection(username).order_by('timestamp', direction=firestore.Query.DESCENDING).limit(20)
    docs = [doc_to_txn(d) for d in q.stream()]
    history = [{
        'id': d.get('_id'),
        'timestamp': d.get('timestamp').strftime('%Y-%m-%d %H:%M:%S') if d.get('timestamp') else None,
        'balance': round(float(d.get('balance', 0.0)), 2),
        'type': d.get('type'),
        'delta': round(float(d.get('delta', 0.0)), 2),
        'note': d.get('note', '')
    } for d in docs]
    out = {
        'current': {
            'balance': round(float(latest.get('balance', 0.0)), 2) if latest else 0.0,
            'timestamp': latest.get('timestamp').strftime('%Y-%m-%d %H:%M:%S') if latest and latest.get('timestamp') else None
        } if latest else {'balance': 0.0, 'timestamp': None},
        'history': history
    }
    return jsonify(out)


@app.route('/api/balance_series')
@login_required
def api_balance_series():
    """
    Return series of balances aggregated by daily / monthly / yearly.
    Uses the same _parse_period_args helper (period + count).
    For each label, we pick the last recorded balance in that label (forward-fill if missing).
    """
    start_dt, end_dt, period = _parse_period_args(request.args)
    # fetch balances in range
    bal_docs = get_balances_in_range(start_dt, end_dt, order_desc=False)

    labels, values = [], []

    if period == 'daily':
        cur_date = start_dt.date()
        endd = end_dt.date()
        days = [(start_dt.date() + relativedelta(days=i)) for i in range((endd - cur_date).days + 1)]
        labels = [d.isoformat() for d in days]
        # map date -> last balance for that date
        date_last = {}
        for b in bal_docs:
            if not b.get('timestamp'):
                continue
            d = b['timestamp'].date().isoformat()
            date_last[d] = float(b.get('balance', 0.0))
        # forward fill
        last_known = None
        for lab in labels:
            if lab in date_last:
                last_known = date_last[lab]
            values.append(round(float(last_known or 0.0), 2))

    elif period == 'monthly':
        cur = date(start_dt.year, start_dt.month, 1)
        endm = date(end_dt.year, end_dt.month, 1)
        months = []
        while cur <= endm:
            months.append(cur)
            cur += relativedelta(months=1)
        labels = [m.strftime('%Y-%m') for m in months]
        month_last = {}
        for b in bal_docs:
            if not b.get('timestamp'):
                continue
            key = b['timestamp'].strftime('%Y-%m')
            month_last[key] = float(b.get('balance', 0.0))
        last_known = None
        for lab in labels:
            if lab in month_last:
                last_known = month_last[lab]
            values.append(round(float(last_known or 0.0), 2))

    elif period == 'yearly':
        years = list(range(start_dt.year, end_dt.year + 1))
        labels = [str(y) for y in years]
        year_last = {}
        for b in bal_docs:
            if not b.get('timestamp'):
                continue
            key = str(b['timestamp'].year)
            year_last[key] = float(b.get('balance', 0.0))
        last_known = None
        for lab in labels:
            if lab in year_last:
                last_known = year_last[lab]
            values.append(round(float(last_known or 0.0), 2))

    else:
        # fallback: daily behavior
        return jsonify({"labels": [], "values": []})

    return jsonify({"labels": labels, "values": values})

@app.route('/api/balance/add', methods=['POST'])
@login_required
def api_balance_add():
    """
    Add balance (increment). Expects JSON { amount: number, note: str (optional) }.
    This creates a new balances doc with fields:
      - balance: new absolute balance after applying add
      - type: 'add'
      - delta: amount (positive)
      - note, timestamp
    """
    username = require_user()
    data = request.get_json() or {}
    try:
        delta = float(data.get('amount', 0.0))
    except Exception:
        return jsonify({"error": "Invalid amount"}), 400
    note = (data.get('note') or '').strip()
    now = datetime.now(UTC)
    latest = get_latest_balance(username=username)
    base = float(latest.get('balance', 0.0)) if latest else 0.0
    new_bal = round(base + delta, 2)
    doc = {
        'balance': float(new_bal),
        'type': 'add',
        'delta': float(delta),
        'note': note,
        'timestamp': now
    }
    bal_collection(username).add(doc)
    return jsonify({"balance": new_bal, "timestamp": now.isoformat(), "type": "add"})


@app.route('/api/balance/sync', methods=['POST'])
@login_required
def api_balance_sync():
    """
    Sync/Set absolute balance. Expects JSON { balance: number, note: str (optional) }.
    Creates a new doc with type 'sync' and delta = new - prev
    """
    username = require_user()
    data = request.get_json() or {}
    try:
        new_balance = float(data.get('balance', 0.0))
    except Exception:
        return jsonify({"error": "Invalid balance value"}), 400
    note = (data.get('note') or '').strip()
    now = datetime.now(UTC)
    latest = get_latest_balance(username=username)
    base = float(latest.get('balance', 0.0)) if latest else 0.0
    delta = round(new_balance - base, 2)
    doc = {
        'balance': float(round(new_balance, 2)),
        'type': 'sync',
        'delta': float(delta),
        'note': note,
        'timestamp': now
    }
    bal_collection(username).add(doc)
    return jsonify({"balance": round(new_balance, 2), "timestamp": now.isoformat(), "type": "sync", "delta": delta})

@app.route('/api/balance/undo', methods=['POST'])
@login_required
def api_balance_undo():
    """
    Delete the most-recent balance document (undo last action).
    If the most-recent entry is a transaction (type 'txn' or 'txn_delete'),
    we refuse and return a helpful error message (undo supports balance add/sync entries).
    Returns the deleted doc summary and the new current balance (if any).
    """
    username = require_user()
    # find last doc
    q = bal_collection(username).order_by('timestamp', direction=firestore.Query.DESCENDING).limit(1)
    docs = list(q.stream())
    if not docs:
        return jsonify({"error": "No balance history to undo"}), 400

    last_doc = docs[0]
    last_data = doc_to_txn(last_doc)
    last_type = (last_data.get('type') or '').lower()

    # Disallow undo when last entry is a transaction
    if last_type in ('txn', 'txn_delete'):
        # Friendly, actionable error for the client
        return jsonify({
            "error": f"Cannot undo: last entry is a transaction ('{last_type}').",
            "reason": "Transactions are persisted separately; undoing them here may corrupt balances.",
            "advice": "To revert a transaction, delete the transaction from the Transactions page instead."
        }), 400

    # safe to delete
    try:
        bal_collection(username).document(last_doc.id).delete()
    except Exception as e:
        app.logger.exception("Failed to delete balance doc %s for user %s: %s", getattr(last_doc, 'id', '<unknown>'), username, e)
        return jsonify({"error": "Delete failed"}), 500

    new_latest = get_latest_balance(username=username)
    new_balance = float(new_latest.get('balance', 0.0)) if new_latest else 0.0

    return jsonify({
        "deleted": {
            "id": last_doc.id,
            "balance": round(float(last_data.get('balance', 0.0)), 2),
            "type": last_data.get('type'),
            "delta": round(float(last_data.get('delta', 0.0)), 2),
            "timestamp": last_data.get('timestamp').strftime('%Y-%m-%d %H:%M:%S') if last_data.get('timestamp') else None,
            "note": last_data.get('note', '')
        },
        "current_balance": round(new_balance, 2)
    })

@app.route('/api/balance/history')
@login_required
def api_balance_history():
    """Return recent balance history (paginated via ?limit=... )"""
    username = require_user()
    limit = max(int(request.args.get('limit', 50)), 1)
    q = bal_collection(username).order_by('timestamp', direction=firestore.Query.DESCENDING).limit(limit)
    docs = [doc_to_txn(d) for d in q.stream()]
    out = [{
        "id": d.get('_id'),
        "timestamp": d.get('timestamp').strftime('%Y-%m-%d %H:%M:%S') if d.get('timestamp') else None,
        "balance": round(float(d.get('balance', 0.0)), 2),
        "type": d.get('type'),
        "delta": round(float(d.get('delta', 0.0)), 2),
        "note": d.get('note', '')
    } for d in docs]
    return jsonify({"history": out})

# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)
