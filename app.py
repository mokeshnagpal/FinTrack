from flask import (
    Flask, render_template, redirect, url_for, flash,
    request, jsonify, send_file, abort, session
)
from functools import wraps

from datetime import datetime, date, timezone, timedelta
from dateutil.relativedelta import relativedelta
from forms import (
    CATEGORY_CHOICES,
    CategoryForm,
    ChangePasswordForm,
    ChangeUsernameForm,
    LoginForm,
    RecurringForm,
    TransactionForm,
    ViewPasswordForm,
    ViewPasswordRevealForm,
)
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
import time
import math
from urllib.parse import urlparse, urljoin
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.security import check_password_hash, generate_password_hash

try:
    import bcrypt
except Exception:
    bcrypt = None

# ---------------------------------------------------------------------
# Early env load (explicit)
# ---------------------------------------------------------------------
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path)

# ----------------------------
# Configuration
# ----------------------------
def env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return str(value).strip().lower() in {'1', 'true', 'yes', 'on'}

def env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default

UTC = timezone.utc
IST = timezone(timedelta(hours=5, minutes=30))
OCCURRENCE_WINDOW_SECS = env_int('OCCURRENCE_WINDOW_SECS', 60)
SESSION_LIFETIME_HOURS = env_int('SESSION_LIFETIME_HOURS', 12)

def now_ist():
    return datetime.now(IST)

def local_datetime_to_utc(local_date, local_time):
    return datetime.combine(local_date, local_time).replace(tzinfo=IST).astimezone(UTC)

def utc_to_ist(value):
    dt = ts_to_dt(value)
    return dt.astimezone(IST) if dt else None

def format_ist(value, fmt='%Y-%m-%d %H:%M:%S'):
    dt = utc_to_ist(value)
    return dt.strftime(fmt) if dt else None

def ist_day_bounds(local_date):
    start = datetime.combine(local_date, datetime.min.time()).replace(tzinfo=IST)
    end = datetime.combine(local_date, datetime.max.time()).replace(tzinfo=IST)
    return start.astimezone(UTC), end.astimezone(UTC)

# read view-only password (strip whitespace)
HW_PASSWORD = os.environ.get('VIEW_PASS')  # could be None
if isinstance(HW_PASSWORD, str):
    HW_PASSWORD = HW_PASSWORD.strip()

# ---------------------------------------------------------------------
# Firebase / Firestore init
# ---------------------------------------------------------------------
firebase_credentials_str = os.environ.get('FIREBASE_CREDENTIALS')
if not firebase_credentials_str:
    raise ValueError("FIREBASE_CREDENTIALS environment variable not set.")

firebase_credentials_dict = json.loads(firebase_credentials_str)

if 'private_key' in firebase_credentials_dict:
    firebase_credentials_dict['private_key'] = firebase_credentials_dict['private_key'].replace('\\n', '\n')

cred = credentials.Certificate(firebase_credentials_dict)

if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)

fs = firestore.client()

SETTINGS_COL = "settings"
VIEW_ONLY_SETTINGS_DOC = "view_only_access"
CATEGORIES_SETTINGS_DOC = "categories"
CLIENT_ACTIONS_COL = "client_actions"
CACHE_TTL_SECONDS = env_int('CACHE_TTL_SECONDS', 300)
AUTH_CACHE_TTL_SECONDS = env_int('AUTH_CACHE_TTL_SECONDS', 7 * 24 * 60 * 60)
WAKE_REFRESH_IDLE_SECONDS = env_int('WAKE_REFRESH_IDLE_SECONDS', 5 * 60)
FIRESTORE_TIMEOUT_SECONDS = env_int('FIRESTORE_TIMEOUT_SECONDS', 8)
ENABLE_DEBUG_ROUTES = env_bool('ENABLE_DEBUG_ROUTES', False)
MAX_MONEY_AMOUNT = 999999999
MAX_DESCRIPTION_LENGTH = 120
MAX_NOTE_LENGTH = 120
_APP_CACHE = {}
_LAST_REQUEST_MONOTONIC = time.monotonic()
_LAST_CACHE_REFRESH_RESULT = None

# ---------------------------------------------------------------------
# Flask App Configuration
# ---------------------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET')
if not app.config['SECRET_KEY']:
    raise ValueError("FLASK_SECRET environment variable not set.")
app.config['SQLALCHEMY_DATABASE_URI'] = 'firestore://'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_REFRESH_EACH_REQUEST'] = False

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=env_bool('FORCE_HTTPS'),
    SESSION_COOKIE_SAMESITE='Lax',
)
app.permanent_session_lifetime = timedelta(hours=SESSION_LIFETIME_HOURS)
csrf = CSRFProtect(app)

LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
app.logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

app.logger.debug("FLASK_SECRET present? %s", bool(app.config.get('SECRET_KEY')))
app.logger.debug("VIEW_PASS present? %s", bool(HW_PASSWORD))


@app.template_filter('ist_datetime')
def ist_datetime_filter(value, fmt='%Y-%m-%d %H:%M'):
    return format_ist(value, fmt) or '-'

# ---------------------------------------------------------------------
# Utilities: timestamp parsing & document conversion
# ---------------------------------------------------------------------
ADMIN_USER_RAW = os.environ.get('ADMIN_USER', '')
ADMIN_USERS = set(u.strip().lower() for u in ADMIN_USER_RAW.split(',') if u.strip())

VIEW_ONLY_ALLOWED_PREFIXES = (
    '/balance',
    '/analytics',
    '/transactions',
    '/api/balance_current',
    '/api/balance_series',
    '/api/totals',
    '/api/category_breakdown',
    '/api/transactions_range',
    '/api/render_status',
    '/export/transactions_csv',
    '/static/',
    '/view',
    '/view-login',
)

def is_valid_user(username):
    """
    Return True if username is allowed:
     - present in ADMIN_USERS env list OR
     - a document exists at users/{username} in Firestore
    Username is normalized to lowercase before checks.
    """
    if not username:
        return False

    normalized_username = normalize_username(username)

    if normalized_username in ADMIN_USERS:
        return True

    try:
        return get_user_auth_doc(normalized_username).exists
    except Exception:
        app.logger.exception("is_valid_user: Firestore check failed for %s", normalized_username)
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
    return user_doc_ref(username).collection('transactions')

def rec_collection(username=None):
    return user_doc_ref(username).collection('recurring')

def bal_collection(username=None):
    return user_doc_ref(username).collection('balances')

def client_actions_collection(username=None):
    return user_doc_ref(username).collection(CLIENT_ACTIONS_COL)

def view_only_settings_ref():
    return fs.collection(SETTINGS_COL).document(VIEW_ONLY_SETTINGS_DOC)

def categories_settings_ref():
    return fs.collection(SETTINGS_COL).document(CATEGORIES_SETTINGS_DOC)

def cache_get(key):
    cached = _APP_CACHE.get(key)
    if not cached:
        return None
    expires_at, value = cached
    if expires_at <= time.monotonic():
        _APP_CACHE.pop(key, None)
        return None
    return value

def cache_set(key, value, ttl=CACHE_TTL_SECONDS):
    _APP_CACHE[key] = (time.monotonic() + ttl, value)
    return value

def cache_delete(key):
    _APP_CACHE.pop(key, None)

def cache_clear():
    _APP_CACHE.clear()

def load_view_only_password_hash_from_store():
    doc = view_only_settings_ref().get(
        retry=None,
        timeout=FIRESTORE_TIMEOUT_SECONDS,
    )
    password_hash = ''
    if doc.exists:
        password_hash = (doc.to_dict() or {}).get('password_hash') or ''
    return cache_set('view_only_password_hash', password_hash)

def load_categories_from_store():
    categories = []
    doc = categories_settings_ref().get(
        retry=None,
        timeout=FIRESTORE_TIMEOUT_SECONDS,
    )
    if doc.exists:
        raw_categories = (doc.to_dict() or {}).get('items') or []
        categories = [normalize_category_name(item) for item in raw_categories]
        categories = [item for item in categories if item]
    if not categories:
        categories = default_categories()
    return list(cache_set('categories', categories))

def load_user_auth_from_store(username):
    normalized_username = normalize_username(username)
    if not normalized_username:
        return {'exists': False, 'data': {}}

    doc = fs.collection('users').document(normalized_username).get(
        retry=None,
        timeout=FIRESTORE_TIMEOUT_SECONDS,
    )
    entry = {
        'exists': doc.exists,
        'data': (doc.to_dict() or {}) if doc.exists else {},
    }
    if entry['exists']:
        cache_user_auth(normalized_username, entry['data'], exists=True)
    else:
        forget_user_auth_cache(normalized_username)
    return freeze_user_auth_entry(entry)

def refresh_cache_job(username=None, reason='manual'):
    global _LAST_CACHE_REFRESH_RESULT

    result = {
        'ok': True,
        'reason': reason,
        'checked_at': datetime.now(UTC).isoformat(),
        'updated': [],
        'errors': [],
    }

    jobs = (
        ('view_only_password', lambda: load_view_only_password_hash_from_store()),
        ('categories', load_categories_from_store),
    )
    for name, loader in jobs:
        try:
            loader()
            result['updated'].append(name)
        except Exception as exc:
            result['ok'] = False
            result['errors'].append(name)
            app.logger.exception("Cache refresh job failed for %s: %s", name, exc)

    normalized_username = normalize_username(username)
    if normalized_username:
        try:
            load_user_auth_from_store(normalized_username)
            result['updated'].append('user_auth')
        except Exception as exc:
            result['ok'] = False
            result['errors'].append('user_auth')
            app.logger.exception("Cache refresh job failed for user_auth user=%s: %s", normalized_username, exc)

    _LAST_CACHE_REFRESH_RESULT = dict(result)
    return result

def refresh_cache_after_wake():
    global _LAST_REQUEST_MONOTONIC

    now_monotonic = time.monotonic()
    idle_seconds = now_monotonic - _LAST_REQUEST_MONOTONIC
    _LAST_REQUEST_MONOTONIC = now_monotonic

    if idle_seconds >= WAKE_REFRESH_IDLE_SECONDS:
        result = refresh_cache_job(get_current_username(), reason='wake')
        app.logger.info(
            "Ran cache refresh job after %.1fs idle/wake pause ok=%s updated=%s",
            idle_seconds,
            result['ok'],
            ','.join(result['updated']),
        )

def normalize_username(username):
    return str(username or '').strip().lower()

def auth_cache_key(username):
    return f"user_auth:{normalize_username(username)}"

def freeze_user_auth_entry(entry):
    return {
        'exists': bool(entry.get('exists')),
        'data': dict(entry.get('data') or {}),
    }

def cache_user_auth(username, user_data=None, exists=True):
    entry = {
        'exists': bool(exists),
        'data': dict(user_data or {}),
    }
    return cache_set(auth_cache_key(username), entry, AUTH_CACHE_TTL_SECONDS)

def forget_user_auth_cache(username):
    cache_delete(auth_cache_key(username))

def get_user_auth_entry(username):
    normalized_username = normalize_username(username)
    if not normalized_username:
        return {'exists': False, 'data': {}}

    cached_entry = cache_get(auth_cache_key(normalized_username))
    if cached_entry is not None:
        return freeze_user_auth_entry(cached_entry)

    return load_user_auth_from_store(normalized_username)

def get_view_only_password_hash():
    cached_hash = cache_get('view_only_password_hash')
    if cached_hash is not None:
        return cached_hash

    try:
        return load_view_only_password_hash_from_store()
    except Exception:
        app.logger.exception("Failed to load view-only password settings")
        return None

def is_view_only_password_configured():
    return bool(get_view_only_password_hash() or HW_PASSWORD)

def default_categories():
    return [label for _, label in CATEGORY_CHOICES]

def normalize_category_name(name):
    return ' '.join(str(name or '').strip().split())

def category_key(name):
    return normalize_category_name(name).lower()

def category_exists(categories, name):
    return category_key(name) in {category_key(item) for item in categories}

def get_categories():
    cached_categories = cache_get('categories')
    if cached_categories is not None:
        return list(cached_categories)

    try:
        return load_categories_from_store()
    except Exception:
        app.logger.exception("Failed to load category settings")
    return list(cache_set('categories', default_categories()))

def save_categories(categories, updated_by=None):
    clean_categories = []
    seen = set()
    for item in categories:
        name = normalize_category_name(item)
        key = name.lower()
        if name and key not in seen:
            clean_categories.append(name)
            seen.add(key)

    if not clean_categories:
        clean_categories = ['Other']

    categories_settings_ref().set({
        'items': clean_categories,
        'updated_at': datetime.now(UTC),
        'updated_by': updated_by,
    }, merge=True)
    cache_set('categories', clean_categories)
    return clean_categories

def apply_category_choices(form, include=None):
    categories = get_categories()
    include_name = normalize_category_name(include)
    if include_name and not category_exists(categories, include_name):
        categories.append(include_name)
    form.category.choices = [(item, item) for item in categories]

def view_password_status_context():
    has_db_password = bool(get_view_only_password_hash())
    can_copy_current_view_password = bool(HW_PASSWORD and not has_db_password)
    return {
        'has_db_password': has_db_password,
        'has_env_fallback': bool(HW_PASSWORD),
        'can_copy_current_view_password': can_copy_current_view_password,
        'current_view_password': HW_PASSWORD if can_copy_current_view_password else '',
    }

def render_management(
    category_form=None,
    categories=None,
    editing_category=None,
    view_form=None,
    reveal_form=None,
    revealed_current_view_password='',
    username_form=None,
    password_form=None,
):
    return render_template(
        'management.html',
        form=view_form or ViewPasswordForm(prefix='view_password'),
        reveal_form=reveal_form or ViewPasswordRevealForm(prefix='reveal_view_password'),
        revealed_current_view_password=revealed_current_view_password,
        username_form=username_form or ChangeUsernameForm(prefix='account_username'),
        password_form=password_form or ChangePasswordForm(prefix='account_password'),
        current_username=get_current_username() or '',
        category_form=category_form or CategoryForm(prefix='category'),
        categories=categories if categories is not None else get_categories(),
        editing_category=editing_category,
        **view_password_status_context(),
    )

def is_safe_redirect_url(target):
    host_url = request.host_url
    ref = urljoin(host_url, target)
    return urlparse(ref).netloc == urlparse(host_url).netloc

def parse_positive_int(value, default=1, max_value=None):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    parsed = max(parsed, 1)
    if max_value is not None:
        parsed = min(parsed, max_value)
    return parsed

def parse_iso_date(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, '%Y-%m-%d').date()
    except (TypeError, ValueError):
        return None

def sanitize_sort(value, allowed, default):
    return value if value in allowed else default

def parse_money(value, field_name='Amount', allow_zero=False, allow_negative=False):
    try:
        amount = float(value)
    except (TypeError, ValueError):
        raise ValueError(f'{field_name} must be a valid number.')

    if not math.isfinite(amount):
        raise ValueError(f'{field_name} must be a finite number.')
    if not allow_negative and amount < 0:
        raise ValueError(f'{field_name} cannot be negative.')
    if not allow_zero and amount == 0:
        raise ValueError(f'{field_name} must be greater than zero.')
    if abs(amount) > MAX_MONEY_AMOUNT:
        raise ValueError(f'{field_name} is too large.')

    return round(amount, 2)

def validate_short_text(value, field_name, max_length=MAX_DESCRIPTION_LENGTH):
    text = str(value or '').strip()
    if not text:
        raise ValueError(f'{field_name} is required.')
    if len(text) > max_length:
        raise ValueError(f'{field_name} must be {max_length} characters or fewer.')
    return text

def validate_optional_note(value):
    note = str(value or '').strip()
    if len(note) > MAX_NOTE_LENGTH:
        raise ValueError(f'Note must be {MAX_NOTE_LENGTH} characters or fewer.')
    return note

def stream_with_timeout(query):
    return query.stream(
        retry=None,
        timeout=FIRESTORE_TIMEOUT_SECONDS,
    )

def login_required(view_fn):
    @wraps(view_fn)
    def wrapped(*args, **kwargs):
        if session.get('logged_in'):
            return view_fn(*args, **kwargs)

        path = request.path or ''

        allowed_prefixes = ['/static/', '/export/', '/login', '/view']
        if any(path.startswith(p) for p in allowed_prefixes):
            return view_fn(*args, **kwargs)

        if session.get('view_only'):
            if path == '/' or any(path.startswith(p) for p in VIEW_ONLY_ALLOWED_PREFIXES):
                return view_fn(*args, **kwargs)
            abort(401, description="Authentication required (view-only session has limited access)")

        return redirect(url_for('login', next=request.path))
    return wrapped

def ts_to_dt(ts):
    if ts is None:
        return None
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=UTC)
        return ts.astimezone(UTC)
    try:
        dt = datetime.fromisoformat(str(ts))
        if dt.tzinfo is None:
            return dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except Exception as e:
        raise ValueError(f"Unsupported timestamp format: {type(ts)} ({e})")

def doc_to_txn(doc):
    if hasattr(doc, 'to_dict'):
        d = doc.to_dict() or {}
    elif isinstance(doc, dict):
        d = dict(doc)
    else:
        d = dict(doc)

    if hasattr(doc, 'id'):
        d['_id'] = doc.id
        d['id'] = doc.id
    elif '_id' in d and 'id' not in d:
        d['id'] = d['_id']
    elif 'id' in d and '_id' not in d:
        d['_id'] = d['id']

    for fld in ('timestamp', 'start_datetime', 'last_applied'):
        if fld in d and d[fld] is not None:
            try:
                d[fld] = ts_to_dt(d[fld])
            except Exception:
                pass

    return d

# ---------------------------------------------------------------------
# Firestore helpers (same as your existing functions)
# ---------------------------------------------------------------------
def get_txns_in_range(start_dt, end_dt, order_desc=True, username=None):
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
    docs = stream_with_timeout(q)
    return [doc_to_txn(doc) for doc in docs]

def get_recurring_active(username=None):
    if username is None:
        username = require_user()
    docs = stream_with_timeout(rec_collection(username).where('active', '==', True))
    return [doc_to_txn(doc) for doc in docs]

# ---------------------------------------------------------------------
# Recurring runner and helpers (kept intact)
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
        docs = list(stream_with_timeout(q))
        return len(docs) > 0
    except Exception as e:
        app.logger.exception("occurrence_exists query failed for %s at %s: %s", recurring_doc_id, occ_dt, e)
        return False

def apply_recurring_up_to_today():
    if not session.get('logged_in'):
        return

    username = require_user()
    now = datetime.now(UTC)
    recs = get_recurring_active(username=username) or []
    app.logger.debug("apply_recurring_up_to_today: %d active recurring rules for user %s", len(recs), username)

    for r in recs:
        rec_id = r.get('_id') or r.get('id')
        if not rec_id:
            app.logger.warning("Recurring rule without id: %s", r)
            continue

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

        if last_applied is None:
            next_occ = start_dt
        else:
            if frequency == 'monthly':
                next_occ = last_applied + relativedelta(months=1)
            elif frequency == 'yearly':
                next_occ = last_applied + relativedelta(years=1)
            else:
                next_occ = last_applied + relativedelta(months=1)

        if last_applied is None and next_occ > now:
            app.logger.debug("Recurring %s next_occ (%s) in future, skipping, current (%s)", rec_id, next_occ, now)
            continue

        rec_ref = rec_collection(username).document(rec_id)

        safety_counter = 0
        while next_occ <= now and safety_counter < 1000:
            safety_counter += 1
            if next_occ.tzinfo is None:
                next_occ = next_occ.replace(tzinfo=UTC)

            try:
                exists = occurrence_exists(rec_id, next_occ, username=username)
            except Exception as e:
                app.logger.exception("Error checking occurrence_exists for %s at %s: %s", rec_id, next_occ, e)
                break

            if exists:
                app.logger.debug("Occurrence already exists for recurring %s at %s", rec_id, next_occ)
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
                try:
                    rec_ref = rec_collection(username).document(rec_id)

                    transaction = fs.transaction()

                    def trans_op(tx):
                        window_start = next_occ - timedelta(seconds=OCCURRENCE_WINDOW_SECS)
                        window_end = next_occ + timedelta(seconds=OCCURRENCE_WINDOW_SECS)
                        q = (tx_collection(username)
                             .where('recurring_id', '==', str(rec_id))
                             .where('timestamp', '>=', window_start)
                             .where('timestamp', '<=', window_end)
                             .limit(1))
                        if len(list(stream_with_timeout(q))) > 0:
                            return
                        new_txn_ref = tx_collection(username).document()
                        tx.set(new_txn_ref, txn_doc)
                        tx.update(rec_ref, {'last_applied': next_occ})

                    transaction.call(trans_op)
                    app.logger.info("Created transaction (txn + last_applied updated) for recurring %s at %s (user=%s)", rec_id, next_occ, username)
                    try:
                        append_balance(-float(txn_doc.get('amount', 0.0)), 'recurring', note=f"recurring:{rec_id}", username=username)
                    except Exception:
                        app.logger.exception("Failed to append balance for recurring %s at %s (user=%s)", rec_id, next_occ, username)
                except Exception as e_tx:
                    app.logger.exception("Transaction write failed for recurring %s at %s: %s - falling back to add() (user=%s)", rec_id, next_occ, e_tx, username)
                    try:
                        tx_collection(username).add(txn_doc)
                        app.logger.info("Created transaction (fallback add) for recurring %s at %s (user=%s)", rec_id, next_occ, username)
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
                        break

            if frequency == 'monthly':
                next_occ = next_occ + relativedelta(months=1)
            elif frequency == 'yearly':
                next_occ = next_occ + relativedelta(years=1)
            else:
                next_occ = next_occ + relativedelta(months=1)

        if safety_counter >= 1000:
            app.logger.error("Safety break triggered for recurring %s after %d iterations", rec_id, safety_counter)

# Run before every request (minimal safe throttling)
@app.before_request
def ensure_recurring_applied():
    refresh_cache_after_wake()

    # Only try to run for logged-in full users
    if not session.get('logged_in'):
        return

    # Don't run for non-GET (avoid running during POSTs which are often quick actions)
    if request.method != 'GET':
        app.logger.debug("Skipping recurring runner: non-GET request (%s)", request.method)
        return

    # Skip static assets and a few known prefixes (fast bailouts)
    skip_prefixes = (
        '/static/',
        '/favicon.ico',
        '/export/',
        '/sync-status',
        '/debug/recurring_run',
        '/api/',
        '/login',
        '/logout',
        '/view',
        '/view-login',
    )
    path = request.path or ''
    if any(path.startswith(p) for p in skip_prefixes):
        app.logger.debug("Skipping recurring runner for path: %s", path)
        return

    # Throttle: run at most once per user every N seconds
    THROTTLE_SECONDS = 5 * 60  # 5 minutes (adjust if you want)
    last_run_iso = session.get('last_recurring_run')  # stored as ISO string
    try:
        if last_run_iso:
            last_run = datetime.fromisoformat(last_run_iso)
            # ensure timezone-aware comparison
            if last_run.tzinfo is None:
                last_run = last_run.replace(tzinfo=UTC)
            elapsed = (datetime.now(UTC) - last_run).total_seconds()
            if elapsed < THROTTLE_SECONDS:
                app.logger.debug("Skipping recurring runner: last run %.1fs ago (throttle %ds).", elapsed, THROTTLE_SECONDS)
                return
    except Exception:
        # if parsing fails, continue and run once (but log)
        app.logger.debug("Couldn't parse last_recurring_run (%s); will attempt runner.", last_run_iso)

    # Finally attempt to apply recurring rules, guarded by try/except
    try:
        # Use UTC now (don't add a manual +5:30 offset)
        # apply_recurring_up_to_today already computes next occurrences relative to now
        apply_recurring_up_to_today()

        # record last run timestamp (ISO, timezone-aware)
        session['last_recurring_run'] = datetime.now(UTC).isoformat()
    except Exception:
        app.logger.exception("Error applying recurring rules (throttled runner)")

# ---------------------------------------------------------------------
# Debug route (diagnostic)
# ---------------------------------------------------------------------
@app.route('/debug/recurring_run')
@login_required
def debug_recurring_run():
    if not ENABLE_DEBUG_ROUTES:
        abort(404)

    if not session.get('logged_in'):
        abort(403, description="Full authentication required")

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
# Routes: Pages
# ---------------------------------------------------------------------

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/sync-status')
@login_required
def sync_status():
    if session.get('view_only'):
        abort(403, description="Full authentication required")
    return render_template('sync_status.html')

@app.route('/api/render_status')
@login_required
def api_render_status():
    cache_refresh = _LAST_CACHE_REFRESH_RESULT
    if request.args.get('refresh_cache') == '1':
        cache_refresh = refresh_cache_job(get_current_username(), reason='render_status')

    return jsonify({
        'ok': True,
        'awake': True,
        'checked_at': datetime.now(UTC).isoformat(),
        'cache_refresh': cache_refresh,
    })

def build_transaction_doc(form):
    txn_datetime = local_datetime_to_utc(
        form.date.data or now_ist().date(),
        form.time.data or now_ist().time(),
    )
    return {
        'amount': parse_money(form.amount.data),
        'description': validate_short_text(form.description.data, 'Description'),
        'category': form.category.data or 'Uncategorized',
        'timestamp': txn_datetime
    }

def clean_client_action_id(value):
    cleaned = ''.join(
        char for char in str(value or '').strip()
        if char.isalnum() or char in {'-', '_', '.'}
    )
    return cleaned[:120]

def build_transaction_doc_from_payload(payload):
    txn_date = parse_iso_date(payload.get('date'))
    if txn_date is None:
        raise ValueError('Date must use YYYY-MM-DD format.')
    try:
        txn_time = datetime.strptime(str(payload.get('time') or ''), '%H:%M').time()
    except (TypeError, ValueError):
        raise ValueError('Time must use HH:MM format.')

    amount = parse_money(payload.get('amount'))

    description = validate_short_text(payload.get('description'), 'Description')

    category = normalize_category_name(payload.get('category')) or 'Uncategorized'
    if not category_exists(get_categories(), category):
        raise ValueError('Select a valid category.')
    return {
        'amount': amount,
        'description': description,
        'category': category,
        'timestamp': local_datetime_to_utc(txn_date, txn_time),
    }

def balance_note_exists(username, note):
    if not note:
        return False
    docs = stream_with_timeout(bal_collection(username).where('note', '==', note).limit(1))
    return any(True for _ in docs)

def create_transaction(username, txn_doc, client_action_id=None):
    action_id = clean_client_action_id(client_action_id)
    if action_id:
        action_ref = client_actions_collection(username).document(action_id)
        action_doc = action_ref.get()
        if action_doc.exists:
            data = action_doc.to_dict() or {}
            return data.get('transaction_id'), True

        doc_ref = tx_collection(username).document(action_id)
        if doc_ref.get().exists:
            note = f"txn:{action_id}"
            if not balance_note_exists(username, note):
                append_balance(-float(txn_doc['amount']), 'txn', note=note, username=username)
            action_ref.set({
                'type': 'transaction_create',
                'transaction_id': action_id,
                'created_at': datetime.now(UTC),
            }, merge=True)
            return action_id, True

        txn_doc = dict(txn_doc)
        txn_doc['client_action_id'] = action_id
        doc_ref.set(txn_doc)
        txn_id = action_id
    else:
        doc_ref, _ = tx_collection(username).add(txn_doc)
        txn_id = getattr(doc_ref, 'id', '')

    append_balance(-float(txn_doc['amount']), 'txn', note=f"txn:{txn_id}", username=username)

    if action_id:
        client_actions_collection(username).document(action_id).set({
            'type': 'transaction_create',
            'transaction_id': txn_id,
            'created_at': datetime.now(UTC),
        }, merge=True)

    return txn_id, False


def populate_transaction_form(form, transaction):
    txn_time = utc_to_ist(transaction.get('timestamp')) or now_ist()
    form.amount.data = transaction.get('amount')
    form.description.data = transaction.get('description') or ''
    form.category.data = transaction.get('category') or 'Other'
    form.date.data = txn_time.date()
    form.time.data = txn_time.time().replace(second=0, microsecond=0, tzinfo=None)


@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    form = TransactionForm()
    apply_category_choices(form)
    if form.validate_on_submit():
        txn_doc = build_transaction_doc(form)
        try:
            username = require_user()
            create_transaction(username, txn_doc)
            app.logger.info("Transaction created user=%s amount=%.2f", username, txn_doc['amount'])
            flash('Transaction added successfully.', 'success')
        except Exception as e:
            app.logger.exception("Failed to add transaction: %s", e)
            flash('Failed to add transaction.', 'warning')

        return redirect(url_for('transactions'))
    return render_template('add.html', form=form, editing=False, tx_id=None)

@app.route('/api/transactions/create', methods=['POST'])
@login_required
def api_transaction_create():
    if not session.get('logged_in'):
        abort(403, description="Full authentication required")

    payload = request.get_json(silent=True) or {}
    try:
        username = require_user()
        txn_doc = build_transaction_doc_from_payload(payload)
        txn_id, duplicate = create_transaction(
            username,
            txn_doc,
            client_action_id=payload.get('client_action_id'),
        )
        app.logger.info(
            "Transaction API create user=%s amount=%.2f duplicate=%s",
            username,
            txn_doc['amount'],
            duplicate,
        )
        return jsonify({
            'ok': True,
            'duplicate': duplicate,
            'transaction_id': txn_id,
        })
    except ValueError as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 400
    except Exception:
        app.logger.exception("Transaction API create failed")
        return jsonify({'ok': False, 'error': 'Failed to create transaction.'}), 500

@app.route('/api/transactions/<string:tx_id>/update', methods=['POST'])
@login_required
def api_transaction_update(tx_id):
    if not session.get('logged_in'):
        abort(403, description="Full authentication required")

    payload = request.get_json(silent=True) or {}
    action_id = clean_client_action_id(payload.get('client_action_id'))
    username = require_user()

    try:
        if action_id:
            action_doc = client_actions_collection(username).document(action_id).get()
            if action_doc.exists:
                return jsonify({'ok': True, 'duplicate': True, 'transaction_id': tx_id})

        doc_ref = tx_collection(username).document(tx_id)
        doc = doc_ref.get()
        if not doc.exists:
            return jsonify({'ok': False, 'error': 'Transaction not found.'}), 404

        existing_txn = doc_to_txn(doc)
        updated_doc = build_transaction_doc_from_payload(payload)
        old_amount = float(existing_txn.get('amount', 0.0))
        new_amount = float(updated_doc.get('amount', 0.0))
        balance_delta = round(old_amount - new_amount, 2)
        balance_note = f"edit_txn:{tx_id}:{action_id}" if action_id else f"edit_txn:{tx_id}"

        if balance_delta and not balance_note_exists(username, balance_note):
            append_balance(balance_delta, 'txn_edit', note=balance_note, username=username)
        doc_ref.update(updated_doc)

        if action_id:
            client_actions_collection(username).document(action_id).set({
                'type': 'transaction_update',
                'transaction_id': tx_id,
                'created_at': datetime.now(UTC),
            }, merge=True)

        app.logger.info("Transaction API update id=%s user=%s", tx_id, username)
        return jsonify({'ok': True, 'duplicate': False, 'transaction_id': tx_id})
    except ValueError as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 400
    except Exception:
        app.logger.exception("Transaction API update failed id=%s", tx_id)
        return jsonify({'ok': False, 'error': 'Failed to update transaction.'}), 500

@app.route('/api/transactions/<string:tx_id>/delete', methods=['POST'])
@login_required
def api_transaction_delete(tx_id):
    if not session.get('logged_in'):
        abort(403, description="Full authentication required")

    payload = request.get_json(silent=True) or {}
    action_id = clean_client_action_id(payload.get('client_action_id'))
    username = require_user()

    try:
        if action_id:
            action_doc = client_actions_collection(username).document(action_id).get()
            if action_doc.exists:
                return jsonify({'ok': True, 'duplicate': True, 'transaction_id': tx_id})

        doc_ref = tx_collection(username).document(tx_id)
        doc = doc_ref.get()
        if not doc.exists:
            if action_id:
                client_actions_collection(username).document(action_id).set({
                    'type': 'transaction_delete',
                    'transaction_id': tx_id,
                    'created_at': datetime.now(UTC),
                }, merge=True)
            return jsonify({'ok': True, 'duplicate': True, 'transaction_id': tx_id})

        txn = doc_to_txn(doc)
        amount = float(txn.get('amount', 0.0))
        balance_note = f"del_txn:{tx_id}:{action_id}" if action_id else f"del_txn:{tx_id}"
        if not balance_note_exists(username, balance_note):
            append_balance(amount, 'txn_delete', note=balance_note, username=username)
        doc_ref.delete()

        if action_id:
            client_actions_collection(username).document(action_id).set({
                'type': 'transaction_delete',
                'transaction_id': tx_id,
                'created_at': datetime.now(UTC),
            }, merge=True)

        app.logger.info("Transaction API delete id=%s user=%s", tx_id, username)
        return jsonify({'ok': True, 'duplicate': False, 'transaction_id': tx_id})
    except Exception:
        app.logger.exception("Transaction API delete failed id=%s", tx_id)
        return jsonify({'ok': False, 'error': 'Failed to delete transaction.'}), 500


@app.route('/edit/<string:tx_id>', methods=['GET', 'POST'])
@login_required
def edit_transaction(tx_id):
    username = require_user()
    doc_ref = tx_collection(username).document(tx_id)
    doc = doc_ref.get()

    if not doc.exists:
        app.logger.warning("Transaction edit requested for missing id=%s user=%s", tx_id, username)
        flash('Transaction not found.', 'warning')
        return redirect(url_for('transactions'))

    existing_txn = doc_to_txn(doc)
    form = TransactionForm()
    apply_category_choices(form, include=existing_txn.get('category'))
    form.submit.label.text = 'Update Transaction'

    if form.validate_on_submit():
        updated_doc = build_transaction_doc(form)
        old_amount = float(existing_txn.get('amount', 0.0))
        new_amount = float(updated_doc.get('amount', 0.0))
        balance_delta = round(old_amount - new_amount, 2)

        try:
            doc_ref.update(updated_doc)
            if balance_delta:
                append_balance(balance_delta, 'txn_edit', note=f"edit_txn:{tx_id}", username=username)
            app.logger.info(
                "Transaction updated id=%s user=%s old_amount=%.2f new_amount=%.2f",
                tx_id,
                username,
                old_amount,
                new_amount,
            )
            flash('Transaction updated.', 'success')
        except Exception as e:
            app.logger.exception("Failed to update transaction %s: %s", tx_id, e)
            flash('Failed to update transaction.', 'warning')
        return redirect(url_for('transactions'))

    populate_transaction_form(form, existing_txn)
    return render_template('add.html', form=form, editing=True, tx_id=tx_id)

@app.route('/transactions')
@login_required
def transactions():
    page = parse_positive_int(request.args.get('page'), default=1)
    per = 10
    search = (request.args.get('q') or '').strip()
    sort_field = sanitize_sort(
        request.args.get('sort'),
        {'timestamp', 'description', 'category', 'amount'},
        'timestamp',
    )
    sort_dir = sanitize_sort(request.args.get('dir'), {'asc', 'desc'}, 'desc')
    direction = firestore.Query.ASCENDING if sort_dir == 'asc' else firestore.Query.DESCENDING
    cursor_id = (request.args.get('cursor') or '').strip()

    username = require_user()
    base_query = tx_collection(username).order_by(sort_field, direction=direction)
    if cursor_id:
        cursor_doc = tx_collection(username).document(cursor_id).get()
        if cursor_doc.exists:
            base_query = base_query.start_after(cursor_doc)

    scan_limit = 150 if search else per + 1
    docs = list(stream_with_timeout(base_query.limit(scan_limit)))

    if search:
        search_key = search.lower()
        filtered_docs = []
        for doc in docs:
            data = doc.to_dict() or {}
            haystack = ' '.join([
                str(data.get('description') or ''),
                str(data.get('category') or ''),
                str(data.get('amount') or ''),
                format_ist(data.get('timestamp')) or '',
            ]).lower()
            if search_key in haystack:
                filtered_docs.append(doc)
            if len(filtered_docs) > per:
                break
        page_docs = filtered_docs[:per]
        has_next = len(filtered_docs) > per or len(docs) == scan_limit
    else:
        page_docs = docs[:per]
        has_next = len(docs) > per

    txns_list = [doc_to_txn(doc) for doc in page_docs]
    has_prev = page > 1
    next_cursor = page_docs[-1].id if page_docs and has_next else None
    current_cursor = cursor_id

    prev_cursor = ''
    cursor_history_key = f"txn_cursors:{username}:{sort_field}:{sort_dir}:{search}"
    cursor_history = session.get(cursor_history_key, {})
    if next_cursor:
        cursor_history[str(page + 1)] = next_cursor
        cursor_history = {
            key: cursor_history[key]
            for key in sorted(cursor_history, key=lambda item: int(item))[-20:]
        }
        session[cursor_history_key] = cursor_history
    if page > 2:
        prev_cursor = cursor_history.get(str(page - 1), '')

    paginate_obj = SimpleNamespace(
        items=txns_list,
        page=page,
        per_page=per,
        has_next=has_next,
        has_prev=has_prev,
        next_num=page + 1 if has_next else None,
        prev_num=page - 1 if has_prev else None,
        next_cursor=next_cursor,
        prev_cursor=prev_cursor,
        current_cursor=current_cursor,
        search=search,
        sort=sort_field,
        direction=sort_dir,
    )

    return render_template('transactions.html', txns=paginate_obj)

@app.route('/delete/<string:tx_id>', methods=['POST'])
@login_required
def delete(tx_id):
    username = require_user()
    doc_ref = tx_collection(username).document(tx_id)
    doc = doc_ref.get()
    if not doc.exists:
        flash('Transaction not found.', 'warning')
        return redirect(url_for('transactions'))

    try:
        txn = doc_to_txn(doc)
        amt = float(txn.get('amount', 0.0))
        doc_ref.delete()
        append_balance(float(amt), 'txn_delete', note=f"del_txn:{tx_id}", username=username)
        flash('Transaction deleted.', 'info')
    except Exception as e:
        app.logger.exception("Failed to delete transaction %s: %s", tx_id, e)
        flash('Failed to delete transaction.', 'warning')

    return redirect(url_for('transactions'))

# ---------------------------------------------------------------------
# Recurring rules endpoints (kept intact)
# ---------------------------------------------------------------------
def build_recurring_doc(form, last_applied=None):
    """Build the Firestore payload for create/edit from validated form data."""
    start_dt = local_datetime_to_utc(form.start_date.data, form.start_time.data)
    return {
        'amount': parse_money(form.amount.data),
        'description': validate_short_text(form.description.data, 'Description'),
        'category': form.category.data or 'Uncategorized',
        'start_datetime': start_dt,
        'frequency': form.frequency.data,
        'last_applied': last_applied,
        'active': True
    }


def populate_recurring_form(form, recurring_rule):
    """Pre-fill WTForms fields from an existing recurring rule document."""
    start_dt = recurring_rule.get('start_datetime')
    if start_dt:
        local_start = utc_to_ist(start_dt)
        form.start_date.data = local_start.date()
        form.start_time.data = local_start.time().replace(second=0, microsecond=0, tzinfo=None)

    form.amount.data = recurring_rule.get('amount')
    form.description.data = recurring_rule.get('description') or ''
    form.category.data = recurring_rule.get('category') or 'Other'
    form.frequency.data = recurring_rule.get('frequency') or 'monthly'


@app.route('/recurring', methods=['GET', 'POST'])
@login_required
def recurring():
    form = RecurringForm()
    apply_category_choices(form)
    if form.validate_on_submit():
        username = require_user()
        rule_doc = build_recurring_doc(form)
        rec_collection(username).add(rule_doc)
        app.logger.info(
            "Recurring rule created for user=%s amount=%.2f frequency=%s start=%s",
            username,
            rule_doc['amount'],
            rule_doc['frequency'],
            rule_doc['start_datetime'].isoformat(),
        )

        flash('Recurring rule saved.', 'success')
        return redirect(url_for('recurring'))

    username = require_user()
    recs = [
        doc_to_txn(doc)
        for doc in stream_with_timeout(
            rec_collection(username).order_by('start_datetime', direction=firestore.Query.DESCENDING)
        )
    ]
    return render_template('recurring.html', form=form, recs=recs, editing=False, edit_id=None)


@app.route('/recurring/edit/<string:r_id>', methods=['GET', 'POST'])
@login_required
def recurring_edit(r_id):
    username = require_user()
    doc_ref = rec_collection(username).document(r_id)
    doc = doc_ref.get()

    if not doc.exists:
        app.logger.warning("Recurring edit requested for missing rule id=%s user=%s", r_id, username)
        flash('Recurring rule not found.', 'warning')
        return redirect(url_for('recurring'))

    recurring_rule = doc_to_txn(doc)
    form = RecurringForm()
    apply_category_choices(form, include=recurring_rule.get('category'))
    form.submit.label.text = 'Update Recurring Rule'

    if form.validate_on_submit():
        # Preserve last_applied so editing metadata does not replay past occurrences.
        update_doc = build_recurring_doc(form, last_applied=recurring_rule.get('last_applied'))
        doc_ref.update(update_doc)
        app.logger.info(
            "Recurring rule updated id=%s user=%s amount=%.2f frequency=%s start=%s last_applied_preserved=%s",
            r_id,
            username,
            update_doc['amount'],
            update_doc['frequency'],
            update_doc['start_datetime'].isoformat(),
            bool(update_doc.get('last_applied')),
        )
        flash('Recurring rule updated.', 'success')
        return redirect(url_for('recurring'))

    populate_recurring_form(form, recurring_rule)
    recs = [
        doc_to_txn(item)
        for item in stream_with_timeout(
            rec_collection(username).order_by('start_datetime', direction=firestore.Query.DESCENDING)
        )
    ]
    return render_template('recurring.html', form=form, recs=recs, editing=True, edit_id=r_id)

@app.route('/recurring/delete/<string:r_id>', methods=['POST'])
@login_required
def recurring_delete(r_id):
    username = require_user()
    doc_ref = rec_collection(username).document(r_id)
    doc = doc_ref.get()

    if not doc.exists:
        app.logger.warning("Recurring delete requested for missing rule id=%s user=%s", r_id, username)
        flash('Recurring rule not found.', 'warning')
        return redirect(url_for('recurring'))

    doc_ref.delete()
    app.logger.info("Recurring rule deleted id=%s user=%s", r_id, username)
    flash('Recurring rule deleted.', 'info')
    return redirect(url_for('recurring'))

@app.route('/analytics')
@login_required
def analytics():
    return render_template('analytics.html')

# ---------------------------------------------------------------------
# Login / View-only routes (Hardened view-only)
# ---------------------------------------------------------------------
# Helper: verify hashed password (supports bcrypt $2* hashes and Werkzeug hashes)
def verify_password(stored_pw: str, provided_pw: str) -> bool:
    """
    Returns True if provided_pw matches stored_pw.
    Supports:
      - bcrypt hashes that start with '$2' (e.g. $2b$...)
      - Werkzeug-style hashes (generate_password_hash)
    """
    if not stored_pw or not provided_pw:
        return False

    stored = str(stored_pw).strip()

    try:
        # bcrypt-style (starts with $2a$, $2b$, $2y$, etc.)
        if stored.startswith("$2") and bcrypt is not None:
            try:
                return bcrypt.checkpw(provided_pw.encode("utf-8"), stored.encode("utf-8"))
            except Exception as e:
                app.logger.debug("bcrypt checkpw failed: %s", e)
                return False

        # Fallback to Werkzeug's check_password_hash (handles pbkdf2:sha256 and similar)
        return check_password_hash(stored, provided_pw)
    except Exception as e:
        app.logger.exception("Password verification error: %s", e)
        return False

# Optional helper to create a new password hash (Werkzeug PBKDF2 by default)
def make_password_hash(password: str) -> str:
    """
    Use this when creating/changing user passwords.
    By default this uses Werkzeug's generate_password_hash (PBKDF2:sha256).
    If you prefer bcrypt, adjust accordingly.
    """
    return generate_password_hash(password)  # e.g. "pbkdf2:sha256:260000$..."

def verify_view_only_password(provided_pw):
    """
    Verify the view-only password against Firestore settings first.
    VIEW_PASS remains a fallback so existing deployments continue to work.
    """
    if not provided_pw:
        return False

    stored_hash = get_view_only_password_hash()
    if stored_hash:
        return verify_password(stored_hash, provided_pw)

    return bool(HW_PASSWORD and provided_pw == HW_PASSWORD)


def get_user_auth_doc(username):
    entry = get_user_auth_entry(username)
    return SimpleNamespace(
        exists=entry['exists'],
        to_dict=lambda: dict(entry['data']),
    )


def verify_current_user_password(username, password):
    user_entry = get_user_auth_entry(username)
    if not user_entry['exists']:
        return False, None

    user_data = user_entry['data']
    if not verify_password(user_data.get('password'), password):
        return False, user_data

    return True, user_data


def copy_user_subcollection(old_user_ref, new_user_ref, name):
    docs = list(old_user_ref.collection(name).stream(
        retry=None,
        timeout=FIRESTORE_TIMEOUT_SECONDS,
    ))
    for doc in docs:
        new_user_ref.collection(name).document(doc.id).set(doc.to_dict() or {})
    return docs


def rename_user_account(old_username, new_username, user_data):
    old_ref = fs.collection('users').document(old_username)
    new_ref = fs.collection('users').document(new_username)
    existing = new_ref.get(retry=None, timeout=FIRESTORE_TIMEOUT_SECONDS)
    if existing.exists:
        raise ValueError('Username already exists.')

    new_data = dict(user_data or {})
    new_data['updated_at'] = datetime.now(UTC)
    new_ref.set(new_data, merge=True)

    copied_docs = []
    for collection_name in ('transactions', 'recurring', 'balances', CLIENT_ACTIONS_COL):
        for doc in copy_user_subcollection(old_ref, new_ref, collection_name):
            copied_docs.append((collection_name, doc.id))

    for collection_name, doc_id in copied_docs:
        old_ref.collection(collection_name).document(doc_id).delete()
    old_ref.delete()


@app.route('/management', methods=['GET', 'POST'])
@login_required
def management():
    username = require_user()
    form = ViewPasswordForm(prefix='view_password')
    reveal_form = ViewPasswordRevealForm(prefix='reveal_view_password')
    category_form = CategoryForm(prefix='category')
    username_form = ChangeUsernameForm(prefix='account_username')
    password_form = ChangePasswordForm(prefix='account_password')
    categories = get_categories()
    action = request.form.get('action')

    if action == 'update_view_password' and form.validate_on_submit():
        password_hash = make_password_hash(form.password.data.strip())
        view_only_settings_ref().set({
            'password_hash': password_hash,
            'updated_at': datetime.now(UTC),
            'updated_by': username,
        }, merge=True)
        cache_set('view_only_password_hash', password_hash)
        app.logger.info("View-only password updated by user=%s", username)
        flash('View-only password updated successfully.', 'success')
        return redirect(url_for('management'))

    if action == 'reveal_view_password' and reveal_form.validate_on_submit():
        entered_password = reveal_form.current_password.data.strip()
        if verify_view_only_password(entered_password):
            app.logger.info("View-only password verified for reveal by user=%s", username)
            return render_management(
                view_form=form,
                reveal_form=reveal_form,
                revealed_current_view_password=entered_password,
                category_form=category_form,
                categories=categories,
                username_form=username_form,
                password_form=password_form,
            )
        flash('Current view-only password is incorrect.', 'danger')

    if action == 'add_category' and category_form.validate_on_submit():
        new_category = normalize_category_name(category_form.name.data)
        if category_exists(categories, new_category):
            flash('Category already exists.', 'warning')
        else:
            save_categories([*categories, new_category], updated_by=username)
            app.logger.info("Category added name=%s user=%s", new_category, username)
            flash('Category added successfully.', 'success')
        return redirect(url_for('management'))

    if action == 'update_username' and username_form.validate_on_submit():
        new_username = normalize_username(username_form.username.data)
        user_doc = get_user_auth_doc(username)
        user_data = user_doc.to_dict() if user_doc.exists else {}
        if new_username == username:
            flash('New username is the same as the current username.', 'warning')
        else:
            try:
                rename_user_account(username, new_username, user_data)
                forget_user_auth_cache(username)
                cache_user_auth(new_username, user_data, exists=True)
                session['username'] = new_username
                app.logger.info("Username changed old=%s new=%s", username, new_username)
                flash('Username updated successfully.', 'success')
                return redirect(url_for('management'))
            except ValueError as exc:
                flash(str(exc), 'warning')
            except Exception:
                app.logger.exception("Failed to update username old=%s new=%s", username, new_username)
                flash('Failed to update username.', 'warning')

    if request.method != 'POST' or action != 'update_username':
        username_form.username.data = username

    if action == 'update_password' and password_form.validate_on_submit():
        current_password = password_form.current_password.data.strip()
        password_ok, user_data = verify_current_user_password(username, current_password)
        if not password_ok:
            flash('Current password is incorrect.', 'danger')
        else:
            password_hash = make_password_hash(password_form.password.data.strip())
            updated_at = datetime.now(UTC)
            user_doc_ref(username).set({
                'password': password_hash,
                'updated_at': updated_at,
            }, merge=True)
            user_data = dict(user_data or {})
            user_data.update({
                'password': password_hash,
                'updated_at': updated_at,
            })
            cache_user_auth(username, user_data, exists=True)
            app.logger.info("Full-login password updated user=%s", username)
            flash('Password updated successfully.', 'success')
            return redirect(url_for('management'))

    if request.method == 'POST' and action not in {
        'update_view_password',
        'reveal_view_password',
        'add_category',
        'update_username',
        'update_password',
    }:
        app.logger.warning("Unknown management action=%s user=%s", action, username)
        flash('Invalid management action.', 'warning')

    return render_management(
        view_form=form,
        reveal_form=reveal_form,
        category_form=category_form,
        categories=categories,
        username_form=username_form,
        password_form=password_form,
    )


@app.route('/management/categories/edit/<path:category_name>', methods=['GET', 'POST'])
@login_required
def management_category_edit(category_name):
    username = require_user()
    original = normalize_category_name(category_name)
    categories = get_categories()
    category_form = CategoryForm(prefix='category')
    category_form.submit.label.text = 'Update Category'

    if not category_exists(categories, original):
        flash('Category not found.', 'warning')
        return redirect(url_for('management'))

    if category_form.validate_on_submit():
        updated = normalize_category_name(category_form.name.data)
        if category_key(updated) != category_key(original) and category_exists(categories, updated):
            flash('Category already exists.', 'warning')
            return redirect(url_for('management_category_edit', category_name=original))

        renamed = [updated if category_key(item) == category_key(original) else item for item in categories]
        save_categories(renamed, updated_by=username)
        app.logger.info("Category renamed old=%s new=%s user=%s", original, updated, username)
        flash('Category updated.', 'success')
        return redirect(url_for('management'))

    category_form.name.data = original
    return render_management(category_form=category_form, categories=categories, editing_category=original)


@app.route('/management/categories/delete/<path:category_name>', methods=['POST'])
@login_required
def management_category_delete(category_name):
    username = require_user()
    category = normalize_category_name(category_name)
    categories = get_categories()
    remaining = [item for item in categories if category_key(item) != category_key(category)]

    if len(remaining) == len(categories):
        flash('Category not found.', 'warning')
        return redirect(url_for('management'))

    if not remaining:
        flash('At least one category is required.', 'warning')
        return redirect(url_for('management'))

    save_categories(remaining, updated_by=username)
    app.logger.info("Category deleted name=%s user=%s", category, username)
    flash('Category deleted.', 'info')
    return redirect(url_for('management'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Full (hashed) login endpoint.
    Renders login.html and performs full authentication using Firestore-stored hashed passwords.
    Successful login sets session['logged_in'] = True and session['username'].
    """
    form = LoginForm()

    # If already logged in (full session), go to index
    if session.get('logged_in'):
        return redirect(url_for('index'))

    # Prevent accidentally re-using view-only flag
    if session.get('view_only'):
        session.pop('view_only', None)

    if form.validate_on_submit():
        username = normalize_username(form.username.data)
        password = (form.password.data or '').strip()

        if not username:
            flash('Please provide a username.', 'danger')
            return render_template('login.html', form=form)

        if not is_valid_user(username):
            flash('Invalid credentials', 'danger')
            return render_template('login.html', form=form)

        try:
            user_entry = get_user_auth_entry(username)
            if not user_entry['exists']:
                app.logger.warning("Login failed: user document not found for %s", username)
                flash('Invalid credentials', 'danger')
                return render_template('login.html', form=form)

            user_data = user_entry['data']
            stored_pw = user_data.get('password')
            if stored_pw is None:
                app.logger.warning("Login failed: user %s has no password set in Firestore", username)
                flash('Invalid credentials', 'danger')
                return render_template('login.html', form=form)

            if verify_password(stored_pw, password):
                # Full, persistent login
                session.pop('view_only', None)
                session['logged_in'] = True
                session.permanent = True
                session['username'] = username
                app.logger.info("User %s logged in (full session)", username)
                flash('Logged in successfully.', 'success')

                next_url = request.args.get('next') or url_for('index')
                if not is_safe_redirect_url(next_url):
                    next_url = url_for('index')
                return redirect(next_url)
            else:
                app.logger.info("Login failed: invalid password for %s", username)
                flash('Invalid credentials', 'danger')

        except Exception as e:
            app.logger.exception("Login error for %s: %s", username, e)
            flash('Login error', 'danger')

    return render_template('login.html', form=form)


@app.route('/view-login', methods=['GET', 'POST'])
def view_login():
    """
    View-only login endpoint.
    Renders view.html and authenticates using the DB-backed view-only password.
    Successful view-only sets session['view_only'] = True and session['username'] (non-privileged).
    """
    form = LoginForm()  # reuse same form (username + password). view.html should post to this endpoint.

    # If already have a full login, redirect to index
    if session.get('logged_in'):
        return redirect(url_for('index'))

    if form.validate_on_submit():
        username = normalize_username(form.username.data)
        password = (form.password.data or '').strip()

        if not username:
            flash('Please provide a username.', 'danger')
            return render_template('view.html', form=form)

        if not is_valid_user(username):
            app.logger.info("View-only login attempted for unknown user %s", username)
            flash('Invalid credentials', 'danger')
            return render_template('view.html', form=form)

        if not is_view_only_password_configured():
            app.logger.error("Attempted view-only login but no view-only password is configured")
            flash('View-only login currently disabled.', 'danger')
            return render_template('view.html', form=form)

        if verify_view_only_password(password):
            session['view_only'] = True
            session['username'] = username
            session.permanent = True
            app.logger.info("View-only session granted for user %s", username)
            flash(f'View-only access granted for user: {username}', 'success')

            next_url = request.args.get('next') or url_for('balance')
            if not is_safe_redirect_url(next_url):
                next_url = url_for('balance')
            return redirect(next_url)
        else:
            app.logger.info("View-only login failed for %s (invalid view password)", username)
            flash('Invalid view-only password.', 'danger')

    # GET or failed POST -> show view-only login template
    return render_template('view.html', form=form)

@app.route('/view', methods=['GET', 'POST'])
def view_only_login():
    """
    Backwards-compatible endpoint:
      - Shows a lightweight form on GET and accepts credentials only by POST.
      - If password matches the DB/env view-only password and username exists => set view-only session.
      - If view-only password does not match but username/password matches Firestore => full login.
    """
    # If already fully logged in, redirect to index
    if session.get('logged_in'):
        return redirect(url_for('index'))

    # If already view-only, go to balance
    if session.get('view_only'):
        return redirect(url_for('balance'))

    # Credentials are accepted only by POST so passwords never appear in URLs.
    if request.method == 'GET':
        password = None
        username = ''
    else:
        password = request.form.get('password') or (request.get_json(silent=True) or {}).get('password')
        username = normalize_username(request.form.get('username'))

    if isinstance(password, str):
        password = password.strip()

    if not is_view_only_password_configured():
        app.logger.warning("View-only attempted but no view-only password is configured.")
        flash('Server misconfiguration: view-only password not configured.', 'danger')
        return redirect(url_for('login'))

    # If username not provided, return small form
    if not username:
        return '''
            <!doctype html>
            <title>View-only access</title>
            <h3>View-only access</h3>
            <form method="post">
              <input type="hidden" name="csrf_token" value="{}" />
              <input name="username" placeholder="Username" />
              <input name="password" placeholder="Password" type="password" />
              <button type="submit">Enter</button>
            </form>
            <p>Passwords are accepted by form submit only.</p>
        '''.format(generate_csrf()), 200

    if verify_view_only_password(password):
        if not is_valid_user(username):
            app.logger.info("View-only attempted for unknown user %s", username)
            flash('Invalid username for view-only access.', 'danger')
            return redirect(url_for('login'))

        session['view_only'] = True
        session['username'] = username
        session.permanent = True
        app.logger.info("View-only session granted for user %s", username)
        flash('View-only access granted.', 'success')
        next_url = request.args.get('next') or url_for('balance')
        if not is_safe_redirect_url(next_url):
            next_url = url_for('balance')
        return redirect(next_url)

    # Otherwise try full login with Firestore password
    try:
        user_entry = get_user_auth_entry(username)
        if not user_entry['exists']:
            app.logger.warning("Login failed: user document not found for %s", username)
            flash('Invalid credentials', 'danger')
            return redirect(url_for('login'))

        user_data = user_entry['data']
        stored_pw = user_data.get('password')
        if stored_pw is None:
            app.logger.warning("Login failed: user %s has no password set in Firestore", username)
            flash('Invalid credentials', 'danger')
            return redirect(url_for('login'))

        if verify_password(stored_pw, password):
            session.pop('view_only', None)
            session['logged_in'] = True
            session.permanent = True
            session['username'] = username
            app.logger.info("User %s logged in (full session) via /view", username)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        else:
            app.logger.info("Login failed: invalid password for %s via /view", username)
            flash('Invalid credentials', 'danger')
            return redirect(url_for('login'))
    except Exception as e:
        app.logger.exception("Error in /view login for %s: %s", username, e)
        flash('Login error', 'danger')
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('view_only', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# ---------------------------------------------------------------------
# API helpers & endpoints
# ---------------------------------------------------------------------
def _parse_period_args(args):
    period = args.get('period', 'daily')
    count = parse_positive_int(args.get('count'), default=30, max_value=366)
    now_local = now_ist()
    from_date = parse_iso_date(args.get('from'))
    to_date = parse_iso_date(args.get('to'))

    if from_date and to_date:
        if from_date > to_date:
            from_date, to_date = to_date, from_date
        start_dt, _ = ist_day_bounds(from_date)
        _, end_dt = ist_day_bounds(to_date)
        return start_dt, end_dt, period if period in {'daily', 'monthly', 'yearly'} else 'daily'

    if period == 'daily':
        end_date = now_local.date()
        start_date = end_date - relativedelta(days=(count - 1))
        start_dt, _ = ist_day_bounds(start_date)
        _, end_dt = ist_day_bounds(end_date)
        return start_dt, end_dt, 'daily'

    if period == 'monthly':
        first_of_current = date(now_local.year, now_local.month, 1)
        start_month = first_of_current - relativedelta(months=(count - 1))
        last_day = first_of_current + relativedelta(months=1) - relativedelta(days=1)
        start_dt, _ = ist_day_bounds(start_month)
        _, end_dt = ist_day_bounds(last_day)
        return start_dt, end_dt, 'monthly'

    if period == 'yearly':
        start_year = date(now_local.year - (count - 1), 1, 1)
        end_year = date(now_local.year, 12, 31)
        start_dt, _ = ist_day_bounds(start_year)
        _, end_dt = ist_day_bounds(end_year)
        return start_dt, end_dt, 'yearly'

    end_date = now_local.date()
    start_date = end_date - relativedelta(days=29)
    start_dt, _ = ist_day_bounds(start_date)
    _, end_dt = ist_day_bounds(end_date)
    return start_dt, end_dt, 'daily'

@app.route('/api/totals')
@login_required
def api_totals():
    start_dt, end_dt, period = _parse_period_args(request.args)
    labels, values = [], []

    txns = get_txns_in_range(start_dt, end_dt, order_desc=False)

    if period == 'daily':
        cur_date = utc_to_ist(start_dt).date()
        endd = utc_to_ist(end_dt).date()
        num_days = (endd - cur_date).days + 1
        results = { (cur_date + relativedelta(days=i)).isoformat(): 0.0 for i in range(num_days) }
        for t in txns:
            d = utc_to_ist(t['timestamp']).date().isoformat()
            results[d] = results.get(d, 0.0) + float(t.get('amount', 0.0))
        labels = list(results.keys())
        values = [round(results[k], 2) for k in results.keys()]

    elif period == 'monthly':
        start_local = utc_to_ist(start_dt)
        end_local = utc_to_ist(end_dt)
        cur = date(start_local.year, start_local.month, 1)
        endm = date(end_local.year, end_local.month, 1)
        months = []
        while cur <= endm:
            months.append(cur)
            cur += relativedelta(months=1)
        labels = [m.strftime('%Y-%m') for m in months]
        month_sums = {m.strftime('%Y-%m'): 0.0 for m in months}
        for t in txns:
            key = utc_to_ist(t['timestamp']).strftime('%Y-%m')
            if key in month_sums:
                month_sums[key] += float(t.get('amount', 0.0))
        values = [round(month_sums[k], 2) for k in labels]

    elif period == 'yearly':
        years = range(utc_to_ist(start_dt).year, utc_to_ist(end_dt).year + 1)
        labels = [str(y) for y in years]
        year_sums = {str(y): 0.0 for y in years}
        for t in txns:
            y = utc_to_ist(t['timestamp']).year
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
            "timestamp": format_ist(largest.get('timestamp'))
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
@login_required
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
@login_required
def api_transactions_range():
    start_dt, end_dt, _ = _parse_period_args(request.args)
    txns = get_txns_in_range(start_dt, end_dt, order_desc=True)
    out = [{
        "id": t.get('_id'),
        "timestamp": format_ist(t.get('timestamp')),
        "description": t.get('description'),
        "category": t.get('category') or 'Uncategorized',
        "amount": round(float(t.get('amount', 0.0)), 2)
    } for t in txns]
    return jsonify({"transactions": out})

@app.route('/export/transactions_csv')
@login_required
def export_transactions_csv():
    start_dt, end_dt, _ = _parse_period_args(request.args)
    txns = get_txns_in_range(start_dt, end_dt, order_desc=False)

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['id', 'timestamp', 'description', 'category', 'amount'])
    for t in txns:
        cw.writerow([
            t.get('_id'),
            format_ist(t.get('timestamp')),
            t.get('description'),
            t.get('category') or '',
            f"{float(t.get('amount', 0.0)):.2f}"
        ])

    buf = io.BytesIO(si.getvalue().encode('utf-8'))
    buf.seek(0)
    filename = f"transactions_{start_dt.strftime('%Y%m%d')}_{end_dt.strftime('%Y%m%d')}.csv"
    return send_file(buf, mimetype='text/csv', as_attachment=True, download_name=filename)

# legacy endpoints
@app.route('/api/daily_totals')
@login_required
def api_daily_totals():
    end = now_ist().date()
    start = end - relativedelta(days=29)
    start_dt, _ = ist_day_bounds(start)
    _, end_dt = ist_day_bounds(end)
    results = {d.isoformat(): 0.0 for d in [start + relativedelta(days=i) for i in range(30)]}
    txns = get_txns_in_range(start_dt, end_dt, order_desc=False)
    for t in txns:
        d = utc_to_ist(t['timestamp']).date().isoformat()
        results[d] = results.get(d, 0.0) + float(t.get('amount', 0.0))
    labels, values = list(results.keys()), [round(results[k], 2) for k in results.keys()]
    return jsonify({"labels": labels, "values": values})

@app.route('/api/monthly_totals')
@login_required
def api_monthly_totals():
    end = now_ist().date()
    months = [end - relativedelta(months=i) for i in range(11, -1, -1)]
    labels = [m.strftime('%Y-%m') for m in months]
    totals = []
    for m in months:
        startm, _ = ist_day_bounds(date(m.year, m.month, 1))
        endm_date = date(m.year, m.month, 1) + relativedelta(months=1) - relativedelta(days=1)
        _, endm = ist_day_bounds(endm_date)
        txns = get_txns_in_range(startm, endm, order_desc=False)
        s = sum([float(t.get('amount', 0.0)) for t in txns])
        totals.append(round(float(s or 0.0), 2))
    return jsonify({"labels": labels, "values": totals})

# ---------------------------------------------------------------------
# Balance helpers & APIs (kept intact)
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
    docs = stream_with_timeout(q)
    return [doc_to_txn(doc) for doc in docs]

def get_latest_balance(username=None):
    if username is None:
        username = require_user()
    q = bal_collection(username).order_by('timestamp', direction=firestore.Query.DESCENDING).limit(1)
    docs = list(stream_with_timeout(q))
    if not docs:
        return None
    return doc_to_txn(docs[0])

def get_previous_balance_before(timestamp, username=None):
    if username is None:
        username = require_user()
    q = (
        bal_collection(username)
        .where('timestamp', '<', timestamp)
        .order_by('timestamp', direction=firestore.Query.DESCENDING)
        .limit(1)
    )
    docs = list(stream_with_timeout(q))
    return doc_to_txn(docs[0]) if docs else None

def shift_balance_entries_after(timestamp, delta, username=None):
    if username is None:
        username = require_user()
    if not delta:
        return 0

    q = (
        bal_collection(username)
        .where('timestamp', '>', timestamp)
        .order_by('timestamp', direction=firestore.Query.ASCENDING)
    )
    count = 0
    for doc in stream_with_timeout(q):
        data = doc.to_dict() or {}
        current_balance = parse_money(
            data.get('balance', 0),
            field_name='Balance value',
            allow_zero=True,
            allow_negative=True,
        )
        bal_collection(username).document(doc.id).update({
            'balance': round(current_balance + delta, 2),
        })
        count += 1
    return count

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
    return render_template('balance.html')

@app.route('/api/balance_current')
@login_required
def api_balance_current():
    username = require_user()
    latest = get_latest_balance(username=username)
    q = bal_collection(username).order_by('timestamp', direction=firestore.Query.DESCENDING).limit(20)
    docs = [doc_to_txn(d) for d in stream_with_timeout(q)]
    history = [{
        'id': d.get('_id'),
        'timestamp': format_ist(d.get('timestamp')) if d.get('timestamp') else None,
        'balance': round(float(d.get('balance', 0.0)), 2),
        'type': d.get('type'),
        'delta': round(float(d.get('delta', 0.0)), 2),
        'note': d.get('note', '')
    } for d in docs]
    out = {
        'current': {
            'balance': round(float(latest.get('balance', 0.0)), 2) if latest else 0.0,
            'timestamp': format_ist(latest.get('timestamp')) if latest and latest.get('timestamp') else None
        } if latest else {'balance': 0.0, 'timestamp': None},
        'history': history
    }
    return jsonify(out)

@app.route('/api/balance_series')
@login_required
def api_balance_series():
    start_dt, end_dt, period = _parse_period_args(request.args)
    bal_docs = get_balances_in_range(start_dt, end_dt, order_desc=False)

    labels, values = [], []

    if period == 'daily':
        cur_date = utc_to_ist(start_dt).date()
        endd = utc_to_ist(end_dt).date()
        days = [(cur_date + relativedelta(days=i)) for i in range((endd - cur_date).days + 1)]
        labels = [d.isoformat() for d in days]
        date_last = {}
        for b in bal_docs:
            if not b.get('timestamp'):
                continue
            d = utc_to_ist(b['timestamp']).date().isoformat()
            date_last[d] = float(b.get('balance', 0.0))
        last_known = None
        for lab in labels:
            if lab in date_last:
                last_known = date_last[lab]
            values.append(round(float(last_known or 0.0), 2))

    elif period == 'monthly':
        start_local = utc_to_ist(start_dt)
        end_local = utc_to_ist(end_dt)
        cur = date(start_local.year, start_local.month, 1)
        endm = date(end_local.year, end_local.month, 1)
        months = []
        while cur <= endm:
            months.append(cur)
            cur += relativedelta(months=1)
        labels = [m.strftime('%Y-%m') for m in months]
        month_last = {}
        for b in bal_docs:
            if not b.get('timestamp'):
                continue
            key = utc_to_ist(b['timestamp']).strftime('%Y-%m')
            month_last[key] = float(b.get('balance', 0.0))
        last_known = None
        for lab in labels:
            if lab in month_last:
                last_known = month_last[lab]
            values.append(round(float(last_known or 0.0), 2))

    elif period == 'yearly':
        years = list(range(utc_to_ist(start_dt).year, utc_to_ist(end_dt).year + 1))
        labels = [str(y) for y in years]
        year_last = {}
        for b in bal_docs:
            if not b.get('timestamp'):
                continue
            key = str(utc_to_ist(b['timestamp']).year)
            year_last[key] = float(b.get('balance', 0.0))
        last_known = None
        for lab in labels:
            if lab in year_last:
                last_known = year_last[lab]
            values.append(round(float(last_known or 0.0), 2))

    else:
        return jsonify({"labels": [], "values": []})

    return jsonify({"labels": labels, "values": values})

@app.route('/api/balance/add', methods=['POST'])
@login_required
def api_balance_add():
    username = require_user()
    data = request.get_json() or {}
    try:
        delta = parse_money(data.get('amount'), field_name='Amount', allow_negative=True)
        note = validate_optional_note(data.get('note'))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
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
    return jsonify({"balance": new_bal, "timestamp": format_ist(now), "type": "add"})

@app.route('/api/balance/sync', methods=['POST'])
@login_required
def api_balance_sync():
    username = require_user()
    data = request.get_json() or {}
    try:
        new_balance = parse_money(
            data.get('balance'),
            field_name='Balance value',
            allow_zero=True,
            allow_negative=True,
        )
        note = validate_optional_note(data.get('note'))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
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
    return jsonify({"balance": round(new_balance, 2), "timestamp": format_ist(now), "type": "sync", "delta": delta})

@app.route('/api/balance/<string:entry_id>/update', methods=['POST'])
@login_required
def api_balance_update(entry_id):
    if not session.get('logged_in'):
        abort(403, description="Full authentication required")

    username = require_user()
    data = request.get_json() or {}
    doc_ref = bal_collection(username).document(entry_id)
    doc = doc_ref.get()
    if not doc.exists:
        return jsonify({"error": "Balance entry not found"}), 404

    entry = doc_to_txn(doc)
    entry_type = (entry.get('type') or '').lower()
    if entry_type not in {'add', 'sync'}:
        return jsonify({"error": "Only manual add/sync balance entries can be edited."}), 400

    try:
        note = validate_optional_note(data.get('note'))
        old_balance = parse_money(
            entry.get('balance', 0),
            field_name='Balance value',
            allow_zero=True,
            allow_negative=True,
        )

        if entry_type == 'add':
            new_delta = parse_money(data.get('delta'), field_name='Delta', allow_negative=True)
            old_delta = parse_money(entry.get('delta', 0), field_name='Delta', allow_negative=True)
            balance_diff = round(new_delta - old_delta, 2)
            new_balance = round(old_balance + balance_diff, 2)
        else:
            new_balance = parse_money(
                data.get('balance'),
                field_name='Balance value',
                allow_zero=True,
                allow_negative=True,
            )
            previous = get_previous_balance_before(entry.get('timestamp'), username=username)
            previous_balance = float(previous.get('balance', 0.0)) if previous else 0.0
            new_delta = round(new_balance - previous_balance, 2)
            balance_diff = round(new_balance - old_balance, 2)

        doc_ref.update({
            'balance': float(new_balance),
            'delta': float(new_delta),
            'note': note,
            'updated_at': datetime.now(UTC),
        })
        shifted = shift_balance_entries_after(entry.get('timestamp'), balance_diff, username=username)
        app.logger.info(
            "Balance entry updated id=%s user=%s type=%s shifted=%s",
            entry_id,
            username,
            entry_type,
            shifted,
        )
        return jsonify({
            "ok": True,
            "balance": round(new_balance, 2),
            "delta": round(new_delta, 2),
            "shifted": shifted,
        })
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        app.logger.exception("Failed to update balance entry id=%s user=%s", entry_id, username)
        return jsonify({"error": "Failed to update balance entry"}), 500

@app.route('/api/balance/undo', methods=['POST'])
@login_required
def api_balance_undo():
    username = require_user()
    q = bal_collection(username).order_by('timestamp', direction=firestore.Query.DESCENDING).limit(1)
    docs = list(stream_with_timeout(q))
    if not docs:
        return jsonify({"error": "No balance history to undo"}), 400

    last_doc = docs[0]
    last_data = doc_to_txn(last_doc)
    last_type = (last_data.get('type') or '').lower()

    if last_type in ('txn', 'txn_delete'):
        return jsonify({
            "error": f"Cannot undo: last entry is a transaction ('{last_type}').",
            "reason": "Transactions are persisted separately; undoing them here may corrupt balances.",
            "advice": "To revert a transaction, delete the transaction from the Transactions page instead."
        }), 400

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
            "timestamp": format_ist(last_data.get('timestamp')) if last_data.get('timestamp') else None,
            "note": last_data.get('note', '')
        },
        "current_balance": round(new_balance, 2)
    })

@app.route('/api/balance/history')
@login_required
def api_balance_history():
    username = require_user()
    limit = parse_positive_int(request.args.get('limit'), default=50, max_value=200)
    q = bal_collection(username).order_by('timestamp', direction=firestore.Query.DESCENDING).limit(limit)
    docs = [doc_to_txn(d) for d in stream_with_timeout(q)]
    out = [{
        "id": d.get('_id'),
        "timestamp": format_ist(d.get('timestamp')) if d.get('timestamp') else None,
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
    app.logger.info("Starting app with VIEW_PASS present? %s", bool(HW_PASSWORD))
    app.logger.info("Starting app with FLASK_SECRET present? %s", bool(app.config.get('SECRET_KEY')))

    app.run(debug=env_bool('FLASK_DEBUG'))




