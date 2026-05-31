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
    RecurringBalanceForm,
    RecurringForm,
    SplitDocumentForm,
    SplitEntryForm,
    SplitPersonForm,
    TransactionForm,
    TripForm,
    ViewPasswordForm,
    ViewPasswordRevealForm,
)
from constants import (
    BALANCE_HISTORY_TABLE_LIMIT,
    BROWSER_CACHE_BALANCE_HISTORY,
    BROWSER_CACHE_RECENT_TRANSACTIONS,
    BROWSER_CACHE_TTL_SECONDS,
    DEFAULT_AUTH_CACHE_TTL_SECONDS,
    DEFAULT_CACHE_TTL_SECONDS,
    DEFAULT_RECURRING_THROTTLE_SECONDS,
    DEFAULT_WAKE_REFRESH_IDLE_SECONDS,
    RECENT_TRANSACTIONS_CACHE_LIMIT,
    RECURRING_RULE_TABLE_LIMIT,
    SPLIT_DOCUMENT_TABLE_LIMIT,
    SPLIT_ENTRY_TABLE_LIMIT,
    SYNC_STATUS_POLL_SECONDS,
    TRANSACTION_PAGE_SIZE,
    TRIP_TABLE_LIMIT,
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
SPLIT_PEOPLE_SETTINGS_DOC = "split_people"
CLIENT_ACTIONS_COL = "client_actions"
CACHE_TTL_SECONDS = env_int('CACHE_TTL_SECONDS', DEFAULT_CACHE_TTL_SECONDS)
AUTH_CACHE_TTL_SECONDS = env_int('AUTH_CACHE_TTL_SECONDS', DEFAULT_AUTH_CACHE_TTL_SECONDS)
WAKE_REFRESH_IDLE_SECONDS = env_int('WAKE_REFRESH_IDLE_SECONDS', DEFAULT_WAKE_REFRESH_IDLE_SECONDS)
RECURRING_THROTTLE_SECONDS = env_int('RECURRING_THROTTLE_SECONDS', DEFAULT_RECURRING_THROTTLE_SECONDS)
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
    if fmt == '%Y-%m-%d %H:%M':
        fmt = "'%y-%m-%d %H:%M"
    return format_ist(value, fmt) or '-'

@app.context_processor
def client_constants_context():
    return {
        'client_constants': {
            'balance_history_table_limit': BALANCE_HISTORY_TABLE_LIMIT,
            'browser_cache_balance_history': BROWSER_CACHE_BALANCE_HISTORY,
            'browser_cache_recent_transactions': RECENT_TRANSACTIONS_CACHE_LIMIT,
            'browser_cache_refresh_timeout_ms': 8000,
            'browser_cache_ttl_seconds': BROWSER_CACHE_TTL_SECONDS,
            'recurring_rule_table_limit': RECURRING_RULE_TABLE_LIMIT,
            'split_document_table_limit': SPLIT_DOCUMENT_TABLE_LIMIT,
            'split_entry_table_limit': SPLIT_ENTRY_TABLE_LIMIT,
            'sync_status_poll_seconds': SYNC_STATUS_POLL_SECONDS,
            'transaction_page_size': TRANSACTION_PAGE_SIZE,
        }
    }

# ---------------------------------------------------------------------
# Utilities: timestamp parsing & document conversion
# ---------------------------------------------------------------------
ADMIN_USER_RAW = os.environ.get('ADMIN_USER', '')
ADMIN_USERS = set(u.strip().lower() for u in ADMIN_USER_RAW.split(',') if u.strip())

VIEW_ONLY_ALLOWED_PREFIXES = (
    '/balance',
    '/balance/analytics',
    '/analytics',
    '/transactions',
    '/splits',
    '/api/balance_current',
    '/api/balance_series',
    '/api/balance_analytics',
    '/api/splits',
    '/api/cache_snapshot',
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

def rec_balance_collection(username=None):
    return user_doc_ref(username).collection('recurring_balances')

def bal_collection(username=None):
    return user_doc_ref(username).collection('balances')

def splits_collection(username=None):
    return user_doc_ref(username).collection('splits')

def trips_collection(username=None):
    return user_doc_ref(username).collection('trips')

def split_entries_collection(split_id, username=None):
    return splits_collection(username).document(str(split_id)).collection('entries')

def client_actions_collection(username=None):
    return user_doc_ref(username).collection(CLIENT_ACTIONS_COL)

def view_only_settings_ref():
    return fs.collection(SETTINGS_COL).document(VIEW_ONLY_SETTINGS_DOC)

def categories_settings_ref():
    return fs.collection(SETTINGS_COL).document(CATEGORIES_SETTINGS_DOC)

def split_people_settings_ref():
    return fs.collection(SETTINGS_COL).document(SPLIT_PEOPLE_SETTINGS_DOC)

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
        ('split_people', load_split_people_from_store),
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

def get_user_auth_for_login(username):
    normalized_username = normalize_username(username)
    if not normalized_username:
        return {'exists': False, 'data': {}}, 'none'

    try:
        return load_user_auth_from_store(normalized_username), 'firestore'
    except Exception:
        cached_entry = cache_get(auth_cache_key(normalized_username))
        if cached_entry is not None:
            app.logger.warning(
                "Using cached auth hash for login because Firestore is unavailable user=%s",
                normalized_username,
            )
            return freeze_user_auth_entry(cached_entry), 'cache'
        raise

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

def default_split_people():
    return ['Me']

def normalize_person_name(name):
    return ' '.join(str(name or '').strip().split())

def person_key(name):
    return normalize_person_name(name).lower()

def person_exists(people, name):
    return person_key(name) in {person_key(item) for item in people}

def load_split_people_from_store():
    people = []
    doc = split_people_settings_ref().get(
        retry=None,
        timeout=FIRESTORE_TIMEOUT_SECONDS,
    )
    if doc.exists:
        raw_people = (doc.to_dict() or {}).get('items') or []
        people = [normalize_person_name(item) for item in raw_people]
        people = [item for item in people if item]
    if not people:
        people = default_split_people()
    return list(cache_set('split_people', people))

def get_split_people():
    cached_people = cache_get('split_people')
    if cached_people is not None:
        return list(cached_people)

    try:
        return load_split_people_from_store()
    except Exception:
        app.logger.exception("Failed to load split people settings")
    return list(cache_set('split_people', default_split_people()))

def save_split_people(people, updated_by=None):
    clean_people = []
    seen = set()
    for item in people:
        name = normalize_person_name(item)
        key = name.lower()
        if name and key not in seen:
            clean_people.append(name)
            seen.add(key)

    if not clean_people:
        clean_people = default_split_people()

    split_people_settings_ref().set({
        'items': clean_people,
        'updated_at': datetime.now(UTC),
        'updated_by': updated_by,
    }, merge=True)
    cache_set('split_people', clean_people)
    return clean_people

def apply_category_choices(form, include=None):
    categories = get_categories()
    include_name = normalize_category_name(include)
    if include_name and not category_exists(categories, include_name):
        categories.append(include_name)
    form.category.choices = [(item, item) for item in categories]

def apply_split_entry_choices(form, person_include=None, category_include=None):
    apply_category_choices(form, include=category_include)
    people = get_split_people()
    include_name = normalize_person_name(person_include)
    if include_name and not person_exists(people, include_name):
        people.append(include_name)
    form.person.choices = [(item, item) for item in people]

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
    split_person_form=None,
    split_people=None,
    editing_split_person=None,
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
        split_person_form=split_person_form or SplitPersonForm(prefix='split_person'),
        split_people=split_people if split_people is not None else get_split_people(),
        editing_split_person=editing_split_person,
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

    for fld in ('timestamp', 'start_datetime', 'last_applied', 'created_at', 'updated_at'):
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

def get_recurring_balance_active(username=None):
    if username is None:
        username = require_user()
    docs = stream_with_timeout(rec_balance_collection(username).where('active', '==', True))
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

def recurring_balance_note(recurring_doc_id, occ_dt):
    occ_key = ts_to_dt(occ_dt).isoformat() if occ_dt else ''
    return f"recurring_balance:{recurring_doc_id}:{occ_key}"

def recurring_balance_occurrence_exists(recurring_doc_id, occ_dt, username=None):
    if username is None:
        username = require_user()
    occurrence_key = recurring_balance_note(recurring_doc_id, occ_dt)
    try:
        q = bal_collection(username).where('recurring_balance_key', '==', occurrence_key).limit(1)
        return len(list(stream_with_timeout(q))) > 0
    except Exception as e:
        app.logger.exception("recurring_balance occurrence check failed for %s at %s: %s", recurring_doc_id, occ_dt, e)
        return False

def next_recurring_occurrence(start_dt, last_applied, frequency):
    if last_applied is None:
        return start_dt
    if frequency == 'yearly':
        return last_applied + relativedelta(years=1)
    return last_applied + relativedelta(months=1)

def advance_recurring_occurrence(current_occurrence, frequency):
    if frequency == 'yearly':
        return current_occurrence + relativedelta(years=1)
    return current_occurrence + relativedelta(months=1)

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

def apply_recurring_balances_up_to_today():
    if not session.get('logged_in'):
        return

    username = require_user()
    now = datetime.now(UTC)
    recs = get_recurring_balance_active(username=username) or []
    app.logger.debug("apply_recurring_balances_up_to_today: %d active recurring balance rules for user %s", len(recs), username)

    for r in recs:
        rec_id = r.get('_id') or r.get('id')
        if not rec_id:
            app.logger.warning("Recurring balance rule without id: %s", r)
            continue

        try:
            start_dt = ts_to_dt(r.get('start_datetime')) if r.get('start_datetime') else now
        except Exception as e:
            app.logger.exception("Failed parsing balance start_datetime for %s: %s", rec_id, e)
            start_dt = now

        try:
            last_applied = ts_to_dt(r.get('last_applied')) if r.get('last_applied') else None
        except Exception as e:
            app.logger.exception("Failed parsing balance last_applied for %s: %s", rec_id, e)
            last_applied = None

        frequency = (r.get('frequency') or 'monthly').lower()
        next_occ = next_recurring_occurrence(start_dt, last_applied, frequency)

        if last_applied is None and next_occ > now:
            app.logger.debug("Recurring balance %s next_occ (%s) in future, skipping", rec_id, next_occ)
            continue

        rec_ref = rec_balance_collection(username).document(rec_id)
        safety_counter = 0

        while next_occ <= now and safety_counter < 1000:
            safety_counter += 1
            if next_occ.tzinfo is None:
                next_occ = next_occ.replace(tzinfo=UTC)

            occurrence_key = recurring_balance_note(rec_id, next_occ)
            if recurring_balance_occurrence_exists(rec_id, next_occ, username=username):
                app.logger.debug("Recurring balance occurrence already exists for %s at %s", rec_id, next_occ)
                try:
                    rec_ref.update({'last_applied': next_occ})
                except Exception as e:
                    app.logger.exception("Failed to update recurring balance last_applied for %s: %s", rec_id, e)
            else:
                amount = float(r.get('amount', 0.0))
                balance_note = (r.get('description') or '').strip()
                try:
                    append_balance(
                        amount,
                        'recurring_balance',
                        note=balance_note,
                        username=username,
                        extra_fields={
                            'recurring_balance_id': str(rec_id),
                            'recurring_balance_key': occurrence_key,
                            'scheduled_for': next_occ,
                        },
                    )
                    rec_ref.update({'last_applied': next_occ})
                    app.logger.info(
                        "Applied recurring balance id=%s user=%s amount=%.2f at=%s",
                        rec_id,
                        username,
                        amount,
                        next_occ,
                    )
                except Exception as e:
                    app.logger.exception("Failed applying recurring balance %s at %s: %s", rec_id, next_occ, e)
                    break

            next_occ = advance_recurring_occurrence(next_occ, frequency)

        if safety_counter >= 1000:
            app.logger.error("Safety break triggered for recurring balance %s after %d iterations", rec_id, safety_counter)

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
    last_run_iso = session.get('last_recurring_run')  # stored as ISO string
    try:
        if last_run_iso:
            last_run = datetime.fromisoformat(last_run_iso)
            # ensure timezone-aware comparison
            if last_run.tzinfo is None:
                last_run = last_run.replace(tzinfo=UTC)
            elapsed = (datetime.now(UTC) - last_run).total_seconds()
            if elapsed < RECURRING_THROTTLE_SECONDS:
                app.logger.debug("Skipping recurring runner: last run %.1fs ago (throttle %ds).", elapsed, RECURRING_THROTTLE_SECONDS)
                return
    except Exception:
        # if parsing fails, continue and run once (but log)
        app.logger.debug("Couldn't parse last_recurring_run (%s); will attempt runner.", last_run_iso)

    # Finally attempt to apply recurring rules, guarded by try/except
    session['last_recurring_run'] = datetime.now(UTC).isoformat()
    try:
        # Use UTC now (don't add a manual +5:30 offset)
        # apply_recurring_up_to_today already computes next occurrences relative to now
        apply_recurring_up_to_today()
    except Exception:
        app.logger.exception("Error applying recurring expense rules (throttled runner)")

    try:
        apply_recurring_balances_up_to_today()
    except Exception:
        app.logger.exception("Error applying recurring balance rules (throttled runner)")

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

@app.route('/api/login_wake_status')
def api_login_wake_status():
    cache_refresh = _LAST_CACHE_REFRESH_RESULT
    if request.args.get('refresh_cache') == '1':
        cache_refresh = refresh_cache_job(reason='login_wake')

    return jsonify({
        'ok': True,
        'awake': True,
        'checked_at': datetime.now(UTC).isoformat(),
        'cache_refresh': cache_refresh,
    })

@app.route('/api/login_password_cache_status')
def api_login_password_cache_status():
    username = normalize_username(request.args.get('username'))
    cache_available = bool(username and cache_get(auth_cache_key(username)) is not None)
    return jsonify({
        'ok': True,
        'cache_available': cache_available,
        'checked_at': datetime.now(UTC).isoformat(),
    })

def serialize_transaction_for_cache(txn):
    return {
        'id': txn.get('_id') or txn.get('id'),
        'timestamp': format_ist(txn.get('timestamp')) if txn.get('timestamp') else None,
        'description': txn.get('description') or '',
        'category': txn.get('category') or 'Uncategorized',
        'amount': round(float(txn.get('amount', 0.0)), 2),
    }

def serialize_balance_for_cache(entry):
    return {
        'id': entry.get('_id') or entry.get('id'),
        'timestamp': format_ist(entry.get('timestamp')) if entry.get('timestamp') else None,
        'balance': round(float(entry.get('balance', 0.0)), 2),
        'type': entry.get('type'),
        'delta': round(float(entry.get('delta', 0.0)), 2),
        'note': entry.get('note', ''),
    }

def serialize_recurring_for_cache(rule):
    return {
        'id': rule.get('_id') or rule.get('id'),
        'amount': round(float(rule.get('amount', 0.0)), 2),
        'description': rule.get('description') or '',
        'frequency': rule.get('frequency') or 'monthly',
        'start_datetime': format_ist(rule.get('start_datetime')) if rule.get('start_datetime') else None,
        'category': rule.get('category') or 'Uncategorized',
    }

def serialize_recurring_balance_for_cache(rule):
    return {
        'id': rule.get('_id') or rule.get('id'),
        'balance': round(float(rule.get('balance', 0.0)), 2),
        'frequency': rule.get('frequency') or 'monthly',
        'start_datetime': format_ist(rule.get('start_datetime')) if rule.get('start_datetime') else None,
        'note': rule.get('note') or '',
    }

def serialize_split_doc_for_cache(doc):
    return {
        'id': doc.get('_id') or doc.get('id'),
        'title': doc.get('title') or '',
        'created_at': format_ist(doc.get('created_at')) if doc.get('created_at') else None,
        'updated_at': format_ist(doc.get('updated_at')) if doc.get('updated_at') else None,
        'is_live': bool(doc.get('is_live')),
    }

@app.route('/api/cache_snapshot')
@login_required
def api_cache_snapshot():
    username = require_user()
    latest_balance = get_latest_balance(username=username)
    balance_docs_raw = [
        doc_to_txn(doc)
        for doc in stream_with_timeout(
            bal_collection(username)
            .order_by('timestamp', direction=firestore.Query.DESCENDING)
            .limit(100)
        )
    ]
    balance_docs = [d for d in balance_docs_raw if d.get('type') not in ('txn', 'transaction')][:BROWSER_CACHE_BALANCE_HISTORY]
    txn_docs = [
        doc_to_txn(doc)
        for doc in stream_with_timeout(
            tx_collection(username)
            .order_by('timestamp', direction=firestore.Query.DESCENDING)
            .limit(BROWSER_CACHE_RECENT_TRANSACTIONS)
        )
    ]
    live_split = get_live_split(username=username)
    recurring_docs = get_recurring_rules_for_page(username)
    recurring_balance_docs = get_recurring_balance_rules_for_page(username)
    splits_docs = get_split_documents(username)
    trips_docs = get_trip_documents(username)

    return jsonify({
        'ok': True,
        'cached_at': datetime.now(UTC).isoformat(),
        'limits': {
            'recent_transactions': BROWSER_CACHE_RECENT_TRANSACTIONS,
            'balance_history': BROWSER_CACHE_BALANCE_HISTORY,
            'split_entries': SPLIT_ENTRY_TABLE_LIMIT,
            'recurring_rules': RECURRING_RULE_TABLE_LIMIT,
            'splits': SPLIT_DOCUMENT_TABLE_LIMIT,
            'trips': TRIP_TABLE_LIMIT,
        },
        'categories': get_categories(),
        'split_people': get_split_people(),
        'balance': {
            'current': {
                'balance': round(float(latest_balance.get('balance', 0.0)), 2) if latest_balance else 0.0,
                'timestamp': format_ist(latest_balance.get('timestamp')) if latest_balance and latest_balance.get('timestamp') else None,
            },
            'history': [serialize_balance_for_cache(entry) for entry in balance_docs],
        },
        'transactions': [serialize_transaction_for_cache(txn) for txn in txn_docs],
        'live_split': build_split_summary(live_split, username=username),
        'recurring_rules': [serialize_recurring_for_cache(r) for r in recurring_docs],
        'recurring_balance_rules': [serialize_recurring_balance_for_cache(r) for r in recurring_balance_docs],
        'splits': [serialize_split_doc_for_cache(d) for d in splits_docs],
        'trips': [serialize_trip_for_cache(t) for t in trips_docs],
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

def get_completed_client_action(username, client_action_id):
    action_id = clean_client_action_id(client_action_id)
    if not action_id:
        return None, ''
    action_doc = client_actions_collection(username).document(action_id).get()
    if not action_doc.exists:
        return None, action_id
    return action_doc.to_dict() or {}, action_id

def save_completed_client_action(username, action_id, action_type, result):
    if not action_id:
        return
    client_actions_collection(username).document(action_id).set({
        'type': action_type,
        'result': result,
        'created_at': datetime.now(UTC),
    }, merge=True)

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


def get_latest_transaction_id(username=None):
    if username is None:
        username = require_user()
    docs = list(
        stream_with_timeout(
            tx_collection(username)
            .order_by('timestamp', direction=firestore.Query.DESCENDING)
            .limit(1)
        )
    )
    return docs[0].id if docs else None


def is_latest_transaction(tx_id, username=None):
    latest_id = get_latest_transaction_id(username=username)
    return bool(latest_id and str(latest_id) == str(tx_id))


def has_newer_transaction_after_edit(tx_id, new_timestamp, username=None):
    if username is None:
        username = require_user()
    docs = stream_with_timeout(
        tx_collection(username)
        .where('timestamp', '>', new_timestamp)
        .order_by('timestamp', direction=firestore.Query.DESCENDING)
        .limit(2)
    )
    return any(str(doc.id) != str(tx_id) for doc in docs)


def latest_transaction_error_response(tx_id=None, username=None, action='mutation'):
    app.logger.warning(
        "Latest-only transaction guard blocked action=%s tx_id=%s user=%s",
        action,
        tx_id,
        username,
    )
    return jsonify({
        'ok': False,
        'error': 'Only the latest transaction can be edited or deleted. Delete the latest transaction first to unlock the previous one.',
    }), 400


def transaction_must_remain_latest_response(tx_id=None, username=None):
    app.logger.warning(
        "Latest transaction edit would no longer remain latest tx_id=%s user=%s",
        tx_id,
        username,
    )
    return jsonify({
        'ok': False,
        'error': 'The edited transaction must remain the latest transaction. Keep its date/time after all previous transactions.',
    }), 400


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
    if request.method == 'GET':
        return redirect(url_for('transactions', add='true'))

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

    # Validation failed
    for fieldName, errorMessages in form.errors.items():
        for err in errorMessages:
            flash(f"{form[fieldName].label.text}: {err}", "danger")
    return redirect(url_for('transactions', add='true'))

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
        app.logger.warning("Transaction API create validation failed user=%s error=%s", get_current_username(), exc)
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
        app.logger.warning("Transaction API update validation failed id=%s user=%s error=%s", tx_id, username, exc)
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

    if request.method == 'GET':
        return redirect(url_for('transactions', edit='true', edit_id=tx_id))

    # POST validation failed
    for fieldName, errorMessages in form.errors.items():
        for err in errorMessages:
            flash(f"{form[fieldName].label.text}: {err}", "danger")
    return redirect(url_for('transactions', edit='true', edit_id=tx_id))

@app.route('/transactions')
@login_required
def transactions():
    page = parse_positive_int(request.args.get('page'), default=1)
    per = TRANSACTION_PAGE_SIZE
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
        latest_transaction_id=get_latest_transaction_id(username=username),
    )

    form = TransactionForm()
    apply_category_choices(form)

    return render_template('transactions.html', txns=paginate_obj, form=form)

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

def build_recurring_balance_doc(form, last_applied=None):
    start_dt = local_datetime_to_utc(form.start_date.data, form.start_time.data)
    return {
        'amount': parse_money(form.amount.data),
        'description': validate_short_text(form.description.data, 'Note'),
        'start_datetime': start_dt,
        'frequency': form.frequency.data,
        'last_applied': last_applied,
        'active': True
    }

def populate_recurring_balance_form(form, recurring_rule):
    start_dt = recurring_rule.get('start_datetime')
    if start_dt:
        local_start = utc_to_ist(start_dt)
        form.start_date.data = local_start.date()
        form.start_time.data = local_start.time().replace(second=0, microsecond=0, tzinfo=None)

    form.amount.data = recurring_rule.get('amount')
    form.description.data = recurring_rule.get('description') or ''
    form.frequency.data = recurring_rule.get('frequency') or 'monthly'

def get_recurring_rules_for_page(username):
    return [
        doc_to_txn(doc)
        for doc in stream_with_timeout(
            rec_collection(username)
            .order_by('start_datetime', direction=firestore.Query.DESCENDING)
            .limit(RECURRING_RULE_TABLE_LIMIT)
        )
    ]

def get_recurring_balance_rules_for_page(username):
    return [
        doc_to_txn(doc)
        for doc in stream_with_timeout(
            rec_balance_collection(username)
            .order_by('start_datetime', direction=firestore.Query.DESCENDING)
            .limit(RECURRING_RULE_TABLE_LIMIT)
        )
    ]


def build_recurring_doc_from_payload(payload, last_applied=None):
    amount = parse_money(payload.get('amount'))
    description = validate_short_text(payload.get('description'), 'Description')
    category = payload.get('category') or 'Uncategorized'
    start_date = parse_iso_date(payload.get('date') or payload.get('start_date'))
    if start_date is None:
        raise ValueError('Start Date must use YYYY-MM-DD format.')
    try:
        start_time = datetime.strptime(str(payload.get('time') or payload.get('start_time') or '00:00'), '%H:%M').time()
    except (TypeError, ValueError):
        raise ValueError('Start Time must use HH:MM format.')

    return {
        'amount': amount,
        'description': description,
        'category': category,
        'start_datetime': local_datetime_to_utc(start_date, start_time),
        'frequency': payload.get('frequency') or 'monthly',
        'last_applied': last_applied,
        'active': True
    }

def build_recurring_balance_doc_from_payload(payload, last_applied=None):
    amount = parse_money(payload.get('amount') or payload.get('balance'))
    description = validate_short_text(payload.get('description') or payload.get('note'), 'Note')
    start_date = parse_iso_date(payload.get('date') or payload.get('start_date'))
    if start_date is None:
        raise ValueError('Start Date must use YYYY-MM-DD format.')
    try:
        start_time = datetime.strptime(str(payload.get('time') or payload.get('start_time') or '00:00'), '%H:%M').time()
    except (TypeError, ValueError):
        raise ValueError('Start Time must use HH:MM format.')

    return {
        'amount': amount,
        'description': description,
        'start_datetime': local_datetime_to_utc(start_date, start_time),
        'frequency': payload.get('frequency') or 'monthly',
        'last_applied': last_applied,
        'active': True
    }


@app.route('/recurring', methods=['GET', 'POST'])
@login_required
def recurring():
    form = RecurringForm()
    balance_form = RecurringBalanceForm()
    apply_category_choices(form)
    if request.method == 'POST':
        if request.is_json:
            username = require_user()
            payload = request.get_json(silent=True) or {}
            rule_doc = build_recurring_doc_from_payload(payload)
            doc_ref = rec_collection(username).document()
            doc_ref.set(rule_doc)
            app.logger.info("Recurring rule created via JSON id=%s user=%s", doc_ref.id, username)
            return jsonify({'ok': True, 'id': doc_ref.id})

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
        else:
            for fieldName, errorMessages in form.errors.items():
                for err in errorMessages:
                    flash(f"{form[fieldName].label.text}: {err}", "danger")
            return redirect(url_for('recurring', add='true'))

    username = require_user()
    return render_template(
        'recurring.html',
        form=form,
        balance_form=balance_form,
        recs=get_recurring_rules_for_page(username),
        balance_recs=get_recurring_balance_rules_for_page(username),
        editing=False,
        edit_id=None,
        balance_editing=False,
        balance_edit_id=None,
    )


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

    if request.is_json:
        payload = request.get_json(silent=True) or {}
        update_doc = build_recurring_doc_from_payload(payload, last_applied=recurring_rule.get('last_applied'))
        doc_ref.update(update_doc)
        app.logger.info("Recurring rule updated via JSON id=%s user=%s", r_id, username)
        return jsonify({'ok': True})

    if form.validate_on_submit():
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

    if request.method == 'GET':
        return redirect(url_for('recurring', edit='true', edit_id=r_id))

    # POST validation failed
    for fieldName, errorMessages in form.errors.items():
        for err in errorMessages:
            flash(f"{form[fieldName].label.text}: {err}", "danger")
    return redirect(url_for('recurring', edit='true', edit_id=r_id))

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

    if request.is_json:
        doc_ref.delete()
        app.logger.info("Recurring rule deleted via JSON id=%s user=%s", r_id, username)
        return jsonify({'ok': True})

    doc_ref.delete()
    app.logger.info("Recurring rule deleted id=%s user=%s", r_id, username)
    flash('Recurring rule deleted.', 'info')
    return redirect(url_for('recurring'))

@app.route('/recurring/balance', methods=['POST'])
@login_required
def recurring_balance():
    form = RecurringBalanceForm()
    if request.is_json:
        username = require_user()
        payload = request.get_json(silent=True) or {}
        rule_doc = build_recurring_balance_doc_from_payload(payload)
        doc_ref = rec_balance_collection(username).document()
        doc_ref.set(rule_doc)
        app.logger.info("Recurring balance rule created via JSON id=%s user=%s", doc_ref.id, username)
        return jsonify({'ok': True, 'id': doc_ref.id})

    if form.validate_on_submit():
        username = require_user()
        rule_doc = build_recurring_balance_doc(form)
        rec_balance_collection(username).add(rule_doc)
        app.logger.info(
            "Recurring balance rule created for user=%s amount=%.2f frequency=%s start=%s",
            username,
            rule_doc['amount'],
            rule_doc['frequency'],
            rule_doc['start_datetime'].isoformat(),
        )
        flash('Recurring balance saved.', 'success')
        return redirect(url_for('recurring'))
    else:
        for fieldName, errorMessages in form.errors.items():
            for err in errorMessages:
                flash(f"{form[fieldName].label.text}: {err}", "danger")
        return redirect(url_for('recurring', add_balance='true'))

@app.route('/recurring/balance/edit/<string:r_id>', methods=['GET', 'POST'])
@login_required
def recurring_balance_edit(r_id):
    username = require_user()
    doc_ref = rec_balance_collection(username).document(r_id)
    doc = doc_ref.get()

    if not doc.exists:
        app.logger.warning("Recurring balance edit requested for missing rule id=%s user=%s", r_id, username)
        flash('Recurring balance rule not found.', 'warning')
        return redirect(url_for('recurring'))

    recurring_rule = doc_to_txn(doc)
    balance_form = RecurringBalanceForm()
    balance_form.submit.label.text = 'Update Recurring Balance'

    if request.is_json:
        payload = request.get_json(silent=True) or {}
        update_doc = build_recurring_balance_doc_from_payload(payload, last_applied=recurring_rule.get('last_applied'))
        doc_ref.update(update_doc)
        app.logger.info("Recurring balance rule updated via JSON id=%s user=%s", r_id, username)
        return jsonify({'ok': True})

    if balance_form.validate_on_submit():
        update_doc = build_recurring_balance_doc(balance_form, last_applied=recurring_rule.get('last_applied'))
        doc_ref.update(update_doc)
        app.logger.info(
            "Recurring balance rule updated id=%s user=%s amount=%.2f frequency=%s start=%s last_applied_preserved=%s",
            r_id,
            username,
            update_doc['amount'],
            update_doc['frequency'],
            update_doc['start_datetime'].isoformat(),
            bool(update_doc.get('last_applied')),
        )
        flash('Recurring balance updated.', 'success')
        return redirect(url_for('recurring'))

    if request.method == 'GET':
        return redirect(url_for('recurring', edit_balance='true', edit_id=r_id))

    # POST validation failed
    for fieldName, errorMessages in balance_form.errors.items():
        for err in errorMessages:
            flash(f"{balance_form[fieldName].label.text}: {err}", "danger")
    return redirect(url_for('recurring', edit_balance='true', edit_id=r_id))

@app.route('/recurring/balance/delete/<string:r_id>', methods=['POST'])
@login_required
def recurring_balance_delete(r_id):
    username = require_user()
    doc_ref = rec_balance_collection(username).document(r_id)
    doc = doc_ref.get()

    if not doc.exists:
        app.logger.warning("Recurring balance delete requested for missing rule id=%s user=%s", r_id, username)
        flash('Recurring balance rule not found.', 'warning')
        return redirect(url_for('recurring'))

    if request.is_json:
        doc_ref.delete()
        app.logger.info("Recurring balance rule deleted via JSON id=%s user=%s", r_id, username)
        return jsonify({'ok': True})

    doc_ref.delete()
    app.logger.info("Recurring balance rule deleted id=%s user=%s", r_id, username)
    flash('Recurring balance deleted.', 'info')
    return redirect(url_for('recurring'))


def build_split_document_doc(form):
    now = datetime.now(UTC)
    return {
        'title': validate_short_text(form.title.data, 'Split name', max_length=80),
        'is_live': True,
        'updated_at': now,
    }

def populate_split_document_form(form, split_doc):
    form.title.data = split_doc.get('title') or ''

def build_split_entry_doc(form):
    entry_datetime = local_datetime_to_utc(
        form.date.data or now_ist().date(),
        form.time.data or now_ist().time(),
    )
    person = normalize_person_name(form.person.data)
    if not person_exists(get_split_people(), person):
        raise ValueError('Select a valid person.')
    category = normalize_category_name(form.category.data) or 'Uncategorized'
    if not category_exists(get_categories(), category):
        raise ValueError('Select a valid category.')
    return {
        'person': person,
        'amount': parse_money(form.amount.data),
        'description': validate_short_text(form.description.data, 'Description'),
        'category': category,
        'timestamp': entry_datetime,
        'updated_at': datetime.now(UTC),
    }

def build_split_entry_doc_from_payload(payload):
    entry_date = parse_iso_date(payload.get('date'))
    if entry_date is None:
        raise ValueError('Date must use YYYY-MM-DD format.')
    try:
        entry_time = datetime.strptime(str(payload.get('time') or ''), '%H:%M').time()
    except (TypeError, ValueError):
        raise ValueError('Time must use HH:MM format.')

    person = normalize_person_name(payload.get('person'))
    if not person_exists(get_split_people(), person):
        raise ValueError('Select a valid person.')

    category = normalize_category_name(payload.get('category')) or 'Uncategorized'
    if not category_exists(get_categories(), category):
        raise ValueError('Select a valid category.')

    return {
        'person': person,
        'amount': parse_money(payload.get('amount')),
        'description': validate_short_text(payload.get('description'), 'Description'),
        'category': category,
        'timestamp': local_datetime_to_utc(entry_date, entry_time),
        'updated_at': datetime.now(UTC),
    }

def populate_split_entry_form(form, entry):
    entry_time = utc_to_ist(entry.get('timestamp')) or now_ist()
    form.person.data = entry.get('person')
    form.amount.data = entry.get('amount')
    form.description.data = entry.get('description') or ''
    form.category.data = entry.get('category') or 'Other'
    form.date.data = entry_time.date()
    form.time.data = entry_time.time().replace(second=0, microsecond=0, tzinfo=None)

def serialize_trip_for_cache(t):
    return {
        'id': t.get('_id') or t.get('id'),
        'name': t.get('name') or '',
        'start_date': format_ist(t.get('start_date'), "'%y-%m-%d") if t.get('start_date') else None,
        'end_date': format_ist(t.get('end_date'), "'%y-%m-%d") if t.get('end_date') else None,
        'description': t.get('description') or '',
        'photo_link': t.get('photo_link') or '',
        'cost_type': t.get('cost_type') or 'fixed',
        'approx_cost': round(float(t.get('approx_cost') or 0.0), 2),
        'split_id': t.get('split_id') or None,
    }

def get_trip_documents(username=None):
    if username is None:
        username = require_user()
    docs = stream_with_timeout(
        trips_collection(username)
        .order_by('start_date', direction=firestore.Query.DESCENDING)
        .limit(TRIP_TABLE_LIMIT)
    )
    trips = []
    for doc in docs:
        t = doc_to_txn(doc)
        if t.get('cost_type') == 'split' and t.get('split_id'):
            try:
                totals = get_split_totals(t['split_id'], username=username)
                num_people = len(totals)
                t['approx_cost'] = round(sum(totals.values()) / num_people, 2) if num_people > 0 else 0.0
            except Exception as e:
                app.logger.error("Error calculating dynamic split cost for trip %s: %s", t.get('_id'), str(e))
                t['approx_cost'] = float(t.get('approx_cost') or 0.0)
        else:
            t['approx_cost'] = float(t.get('approx_cost') or 0.0)
        trips.append(t)
    return trips

def get_trip_split_map(username):
    docs = stream_with_timeout(trips_collection(username))
    split_map = {}
    for doc in docs:
        t = doc_to_txn(doc)
        if t.get('split_id'):
            split_map[t['split_id']] = {
                'id': t.get('_id') or doc.id,
                'name': t.get('name') or 'Untitled Trip'
            }
    return split_map

def get_split_documents(username=None):
    if username is None:
        username = require_user()
    docs = stream_with_timeout(
        splits_collection(username)
        .order_by('updated_at', direction=firestore.Query.DESCENDING)
        .limit(SPLIT_DOCUMENT_TABLE_LIMIT)
    )
    return [doc_to_txn(doc) for doc in docs]

def get_live_split(username=None):
    if username is None:
        username = require_user()
    docs = [doc_to_txn(doc) for doc in stream_with_timeout(
        splits_collection(username).where('is_live', '==', True)
    )]
    docs.sort(key=lambda item: item.get('updated_at') or datetime.min.replace(tzinfo=UTC), reverse=True)
    return docs[0] if docs else None

def set_live_split(split_id, username=None):
    if username is None:
        username = require_user()
    now = datetime.now(UTC)
    for doc in stream_with_timeout(splits_collection(username).where('is_live', '==', True)):
        if str(doc.id) != str(split_id):
            splits_collection(username).document(doc.id).set({'is_live': False, 'updated_at': now}, merge=True)
    splits_collection(username).document(str(split_id)).set({'is_live': True, 'updated_at': now}, merge=True)

def get_split_entries(split_id, username=None, limit=SPLIT_ENTRY_TABLE_LIMIT):
    if username is None:
        username = require_user()
    docs = stream_with_timeout(
        split_entries_collection(split_id, username)
        .order_by('timestamp', direction=firestore.Query.DESCENDING)
        .limit(limit)
    )
    return [doc_to_txn(doc) for doc in docs]

def get_split_totals(split_id, username=None):
    if username is None:
        username = require_user()
    totals = {}
    docs = stream_with_timeout(split_entries_collection(split_id, username).order_by('person'))
    for doc in docs:
        entry = doc_to_txn(doc)
        person = normalize_person_name(entry.get('person')) or 'Unknown'
        totals[person] = round(totals.get(person, 0.0) + float(entry.get('amount', 0.0)), 2)
    return totals

def serialize_split_entry(entry):
    return {
        'id': entry.get('_id') or entry.get('id'),
        'person': entry.get('person') or '',
        'amount': round(float(entry.get('amount', 0.0)), 2),
        'description': entry.get('description') or '',
        'category': entry.get('category') or '',
        'timestamp': format_ist(entry.get('timestamp')) if entry.get('timestamp') else None,
    }

def build_split_summary(split_doc, username=None):
    if not split_doc:
        return None
    split_id = split_doc.get('_id') or split_doc.get('id')
    totals = get_split_totals(split_id, username=username)
    entries = get_split_entries(split_id, username=username, limit=SPLIT_ENTRY_TABLE_LIMIT)
    return {
        'id': split_id,
        'title': split_doc.get('title') or 'Untitled split',
        'is_live': bool(split_doc.get('is_live')),
        'updated_at': format_ist(split_doc.get('updated_at')) if split_doc.get('updated_at') else None,
        'totals': [{'person': person, 'amount': amount} for person, amount in sorted(totals.items())],
        'entries': [serialize_split_entry(entry) for entry in entries],
    }

def create_split_entry(username, split_id, entry_doc, client_action_id=None):
    action_id = clean_client_action_id(client_action_id)
    if action_id:
        completed, _ = get_completed_client_action(username, action_id)
        if completed:
            return completed.get('result', {}).get('entry_id'), True

    split_ref = splits_collection(username).document(split_id)
    if not split_ref.get().exists:
        raise LookupError('Split not found.')

    entry_doc = dict(entry_doc)
    entry_doc['created_at'] = entry_doc.get('created_at') or datetime.now(UTC)
    entry_ref = split_entries_collection(split_id, username).document(action_id) if action_id else split_entries_collection(split_id, username).document()
    entry_ref.set(entry_doc, merge=True)
    split_ref.set({'updated_at': datetime.now(UTC)}, merge=True)

    if action_id:
        save_completed_client_action(
            username,
            action_id,
            'split_entry_create',
            {'split_id': split_id, 'entry_id': entry_ref.id},
        )

    return entry_ref.id, False


@app.route('/splits', methods=['GET', 'POST'])
@login_required
def splits():
    username = require_user()
    form = SplitDocumentForm()
    if session.get('view_only'):
        form = SplitDocumentForm(formdata=None)

    if not session.get('view_only') and request.method == 'POST':
        # JSON API payload check
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            title = validate_short_text(payload.get('title'), 'Title')
            is_live = bool(payload.get('is_live'))
            split_doc = {
                'title': title,
                'is_live': is_live,
                'created_at': datetime.now(UTC),
                'updated_at': datetime.now(UTC),
            }
            doc_ref = splits_collection(username).document()
            doc_ref.set(split_doc)
            if is_live:
                set_live_split(doc_ref.id, username=username)
            app.logger.info("Split created via JSON id=%s user=%s live=%s", doc_ref.id, username, is_live)
            return jsonify({'ok': True, 'id': doc_ref.id})

        if form.validate_on_submit():
            split_doc = build_split_document_doc(form)
            split_doc['created_at'] = datetime.now(UTC)
            doc_ref = splits_collection(username).document()
            doc_ref.set(split_doc)
            if split_doc.get('is_live'):
                set_live_split(doc_ref.id, username=username)
            app.logger.info("Split created id=%s user=%s live=%s", doc_ref.id, username, split_doc.get('is_live'))
            flash('Split created.', 'success')
            return redirect(url_for('split_detail', split_id=doc_ref.id))
        else:
            app.logger.warning("Split create validation failed user=%s errors=%s", username, form.errors)
            for fieldName, errorMessages in form.errors.items():
                for err in errorMessages:
                    flash(f"{form[fieldName].label.text}: {err}", "danger")
            return redirect(url_for('splits', add='true'))

    return render_template(
        'splits.html',
        form=form,
        splits=get_split_documents(username=username),
        live_split=get_live_split(username=username),
        trip_map=get_trip_split_map(username=username),
        editing=False,
        edit_id=None,
    )


@app.route('/splits/<string:split_id>')
@login_required
def split_detail(split_id):
    username = require_user()
    split_ref = splits_collection(username).document(split_id)
    split_doc = split_ref.get()
    if not split_doc.exists:
        app.logger.warning("Split detail requested for missing split id=%s user=%s", split_id, username)
        flash('Split not found.', 'warning')
        return redirect(url_for('splits'))

    split_data = doc_to_txn(split_doc)
    entry_form = SplitEntryForm()
    apply_split_entry_choices(entry_form)
    return render_template(
        'split_detail.html',
        split_doc=split_data,
        entry_form=entry_form,
        entries=get_split_entries(split_id, username=username),
        totals=get_split_totals(split_id, username=username),
        editing_entry=False,
        entry_id=None,
    )


@app.route('/splits/edit/<string:split_id>', methods=['GET', 'POST'])
@login_required
def split_edit(split_id):
    if session.get('view_only'):
        abort(401, description="View-only sessions cannot edit splits")
    username = require_user()
    doc_ref = splits_collection(username).document(split_id)
    doc = doc_ref.get()
    if not doc.exists:
        app.logger.warning("Split edit requested for missing split id=%s user=%s", split_id, username)
        flash('Split not found.', 'warning')
        return redirect(url_for('splits'))

    split_doc = doc_to_txn(doc)
    form = SplitDocumentForm()
    form.submit.label.text = 'Update Split'
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        title = validate_short_text(payload.get('title'), 'Title')
        update_doc = {
            'title': title,
            'updated_at': datetime.now(UTC),
        }
        doc_ref.set(update_doc, merge=True)
        app.logger.info("Split updated via JSON id=%s user=%s", split_id, username)
        return jsonify({'ok': True})

    if form.validate_on_submit():
        update_doc = build_split_document_doc(form)
        update_doc['is_live'] = bool(split_doc.get('is_live'))
        update_doc['created_at'] = split_doc.get('created_at') or datetime.now(UTC)
        doc_ref.set(update_doc, merge=True)
        if update_doc.get('is_live'):
            set_live_split(split_id, username=username)
        app.logger.info("Split updated id=%s user=%s live=%s", split_id, username, update_doc.get('is_live'))
        flash('Split updated.', 'success')
        return redirect(url_for('splits'))

    if request.method == 'GET':
        return redirect(url_for('splits', edit='true', edit_id=split_id))

    # POST validation failed
    for fieldName, errorMessages in form.errors.items():
        for err in errorMessages:
            flash(f"{form[fieldName].label.text}: {err}", "danger")
    return redirect(url_for('splits', edit='true', edit_id=split_id))


@app.route('/splits/delete/<string:split_id>', methods=['POST'])
@login_required
def split_delete(split_id):
    if session.get('view_only'):
        abort(401, description="View-only sessions cannot delete splits")
    username = require_user()
    doc_ref = splits_collection(username).document(split_id)
    doc = doc_ref.get()
    if not doc.exists:
        app.logger.warning("Split delete requested for missing split id=%s user=%s", split_id, username)
        flash('Split not found.', 'warning')
        return redirect(url_for('splits'))

    if request.is_json:
        for entry in stream_with_timeout(split_entries_collection(split_id, username)):
            split_entries_collection(split_id, username).document(entry.id).delete()
        doc_ref.delete()
        app.logger.info("Split deleted via JSON id=%s user=%s", split_id, username)
        return jsonify({'ok': True})

    for entry in stream_with_timeout(split_entries_collection(split_id, username)):
        split_entries_collection(split_id, username).document(entry.id).delete()
    doc_ref.delete()
    app.logger.info("Split deleted id=%s user=%s", split_id, username)
    flash('Split deleted.', 'info')
    return redirect(url_for('splits'))


@app.route('/splits/<string:split_id>/live', methods=['POST'])
@login_required
def split_make_live(split_id):
    if session.get('view_only'):
        abort(401, description="View-only sessions cannot change live splits")
    username = require_user()
    doc = splits_collection(username).document(split_id).get()
    if not doc.exists:
        app.logger.warning("Split live update requested for missing split id=%s user=%s", split_id, username)
        flash('Split not found.', 'warning')
        return redirect(url_for('splits'))
    if request.is_json:
        set_live_split(split_id, username=username)
        app.logger.info("Split marked live via JSON id=%s user=%s", split_id, username)
        return jsonify({'ok': True})

    set_live_split(split_id, username=username)
    app.logger.info("Split marked live id=%s user=%s", split_id, username)
    flash('Live split updated.', 'success')
    return redirect(url_for('splits'))


@app.route('/splits/<string:split_id>/unlive', methods=['POST'])
@login_required
def split_remove_live(split_id):
    if session.get('view_only'):
        abort(401, description="View-only sessions cannot change live splits")
    username = require_user()
    doc_ref = splits_collection(username).document(split_id)
    doc = doc_ref.get()
    if not doc.exists:
        app.logger.warning("Split unlive requested for missing split id=%s user=%s", split_id, username)
        flash('Split not found.', 'warning')
        return redirect(url_for('splits'))
    now = datetime.now(UTC)
    if request.is_json:
        doc_ref.set({'is_live': False, 'updated_at': now}, merge=True)
        app.logger.info("Split live removed via JSON id=%s user=%s", split_id, username)
        return jsonify({'ok': True})

    doc_ref.set({'is_live': False, 'updated_at': now}, merge=True)
    app.logger.info("Split live removed id=%s user=%s", split_id, username)
    flash('Live split status removed.', 'info')
    return redirect(url_for('splits'))


@app.route('/splits/<string:split_id>/entries', methods=['POST'])
@login_required
def split_entry_add(split_id):
    if session.get('view_only'):
        abort(401, description="View-only sessions cannot add split entries")
    username = require_user()
    if not splits_collection(username).document(split_id).get().exists:
        app.logger.warning("Split entry add requested for missing split id=%s user=%s", split_id, username)
        flash('Split not found.', 'warning')
        return redirect(url_for('splits'))

    form = SplitEntryForm()
    apply_split_entry_choices(form)
    if form.validate_on_submit():
        try:
            entry_doc = build_split_entry_doc(form)
            create_split_entry(username, split_id, entry_doc)
            app.logger.info("Split entry added split=%s user=%s person=%s amount=%.2f", split_id, username, entry_doc['person'], entry_doc['amount'])
            flash('Split entry added.', 'success')
            return redirect(url_for('split_detail', split_id=split_id))
        except ValueError as exc:
            app.logger.warning("Split entry validation failed split=%s user=%s error=%s", split_id, username, exc)
            flash(str(exc), 'warning')
            return redirect(url_for('split_detail', split_id=split_id, add='true'))
    else:
        app.logger.warning("Split entry form validation failed split=%s user=%s errors=%s", split_id, username, form.errors)
        for fieldName, errorMessages in form.errors.items():
            for err in errorMessages:
                flash(f"{form[fieldName].label.text}: {err}", "danger")
        return redirect(url_for('split_detail', split_id=split_id, add='true'))


@app.route('/splits/<string:split_id>/entries/<string:entry_id>/edit', methods=['GET', 'POST'])
@login_required
def split_entry_edit(split_id, entry_id):
    if session.get('view_only'):
        abort(401, description="View-only sessions cannot edit split entries")
    username = require_user()
    split_doc = splits_collection(username).document(split_id).get()
    if not split_doc.exists:
        app.logger.warning("Split entry edit requested for missing split id=%s entry=%s user=%s", split_id, entry_id, username)
        flash('Split not found.', 'warning')
        return redirect(url_for('splits'))
    entry_ref = split_entries_collection(split_id, username).document(entry_id)
    entry_doc = entry_ref.get()
    if not entry_doc.exists:
        app.logger.warning("Split entry edit requested for missing entry split=%s entry=%s user=%s", split_id, entry_id, username)
        flash('Split entry not found.', 'warning')
        return redirect(url_for('split_detail', split_id=split_id))

    entry = doc_to_txn(entry_doc)
    form = SplitEntryForm()
    form.submit.label.text = 'Update Entry'
    apply_split_entry_choices(form, person_include=entry.get('person'), category_include=entry.get('category'))
    if form.validate_on_submit():
        try:
            update_doc = build_split_entry_doc(form)
            update_doc['created_at'] = entry.get('created_at') or datetime.now(UTC)
            entry_ref.set(update_doc, merge=True)
            splits_collection(username).document(split_id).set({'updated_at': datetime.now(UTC)}, merge=True)
            app.logger.info("Split entry updated split=%s entry=%s user=%s", split_id, entry_id, username)
            flash('Split entry updated.', 'success')
            return redirect(url_for('split_detail', split_id=split_id))
        except ValueError as exc:
            app.logger.warning("Split entry update validation failed split=%s entry=%s user=%s error=%s", split_id, entry_id, username, exc)
            flash(str(exc), 'warning')
            return redirect(url_for('split_detail', split_id=split_id, edit='true', edit_id=entry_id))

    if request.method == 'GET':
        return redirect(url_for('split_detail', split_id=split_id, edit='true', edit_id=entry_id))

    # POST validation failed
    for fieldName, errorMessages in form.errors.items():
        for err in errorMessages:
            flash(f"{form[fieldName].label.text}: {err}", "danger")
    return redirect(url_for('split_detail', split_id=split_id, edit='true', edit_id=entry_id))


@app.route('/splits/<string:split_id>/entries/<string:entry_id>/delete', methods=['POST'])
@login_required
def split_entry_delete(split_id, entry_id):
    if session.get('view_only'):
        abort(401, description="View-only sessions cannot delete split entries")
    username = require_user()
    entry_ref = split_entries_collection(split_id, username).document(entry_id)
    if not entry_ref.get().exists:
        app.logger.warning("Split entry delete requested for missing entry split=%s entry=%s user=%s", split_id, entry_id, username)
        flash('Split entry not found.', 'warning')
        return redirect(url_for('split_detail', split_id=split_id))
    entry_ref.delete()
    splits_collection(username).document(split_id).set({'updated_at': datetime.now(UTC)}, merge=True)
    app.logger.info("Split entry deleted split=%s entry=%s user=%s", split_id, entry_id, username)
    flash('Split entry deleted.', 'info')
    return redirect(url_for('split_detail', split_id=split_id))


@app.route('/api/splits/<string:split_id>/entries/create', methods=['POST'])
@login_required
def api_split_entry_create(split_id):
    if not session.get('logged_in'):
        abort(403, description="Full authentication required")

    payload = request.get_json(silent=True) or {}
    username = require_user()
    try:
        entry_doc = build_split_entry_doc_from_payload(payload)
        entry_id, duplicate = create_split_entry(
            username,
            split_id,
            entry_doc,
            client_action_id=payload.get('client_action_id'),
        )
        app.logger.info(
            "Split entry API create split=%s entry=%s user=%s duplicate=%s",
            split_id,
            entry_id,
            username,
            duplicate,
        )
        split_doc = doc_to_txn(splits_collection(username).document(split_id).get())
        return jsonify({
            'ok': True,
            'duplicate': duplicate,
            'split_id': split_id,
            'entry_id': entry_id,
            'split': build_split_summary(split_doc, username=username),
        })
    except LookupError as exc:
        app.logger.warning("Split entry API create requested for missing split=%s user=%s", split_id, username)
        return jsonify({'ok': False, 'error': str(exc)}), 404
    except ValueError as exc:
        app.logger.warning("Split entry API create validation failed split=%s user=%s error=%s", split_id, username, exc)
        return jsonify({'ok': False, 'error': str(exc)}), 400
    except Exception:
        app.logger.exception("Split entry API create failed split=%s", split_id)
        return jsonify({'ok': False, 'error': 'Failed to create split entry.'}), 500


@app.route('/api/splits/<string:split_id>/entries/<string:entry_id>/update', methods=['POST'])
@login_required
def api_split_entry_update(split_id, entry_id):
    if not session.get('logged_in'):
        abort(403, description="Full authentication required")

    payload = request.get_json(silent=True) or {}
    action_id = clean_client_action_id(payload.get('client_action_id'))
    username = require_user()
    try:
        if action_id:
            completed, _ = get_completed_client_action(username, action_id)
            if completed:
                return jsonify({'ok': True, 'duplicate': True, 'split_id': split_id, 'entry_id': entry_id})

        split_doc = splits_collection(username).document(split_id).get()
        if not split_doc.exists:
            app.logger.warning("Split entry API update requested for missing split=%s entry=%s user=%s", split_id, entry_id, username)
            return jsonify({'ok': False, 'error': 'Split not found.'}), 404

        entry_ref = split_entries_collection(split_id, username).document(entry_id)
        entry_doc = entry_ref.get()
        if not entry_doc.exists:
            app.logger.warning("Split entry API update requested for missing entry split=%s entry=%s user=%s", split_id, entry_id, username)
            return jsonify({'ok': False, 'error': 'Split entry not found.'}), 404

        existing = doc_to_txn(entry_doc)
        update_doc = build_split_entry_doc_from_payload(payload)
        update_doc['created_at'] = existing.get('created_at') or datetime.now(UTC)
        entry_ref.set(update_doc, merge=True)
        splits_collection(username).document(split_id).set({'updated_at': datetime.now(UTC)}, merge=True)

        if action_id:
            save_completed_client_action(
                username,
                action_id,
                'split_entry_update',
                {'split_id': split_id, 'entry_id': entry_id},
            )

        app.logger.info("Split entry API update split=%s entry=%s user=%s", split_id, entry_id, username)
        return jsonify({
            'ok': True,
            'duplicate': False,
            'split_id': split_id,
            'entry_id': entry_id,
            'split': build_split_summary(doc_to_txn(split_doc), username=username),
        })
    except ValueError as exc:
        app.logger.warning("Split entry API update validation failed split=%s entry=%s user=%s error=%s", split_id, entry_id, username, exc)
        return jsonify({'ok': False, 'error': str(exc)}), 400
    except Exception:
        app.logger.exception("Split entry API update failed split=%s entry=%s", split_id, entry_id)
        return jsonify({'ok': False, 'error': 'Failed to update split entry.'}), 500


@app.route('/api/splits/<string:split_id>/entries/<string:entry_id>/delete', methods=['POST'])
@login_required
def api_split_entry_delete(split_id, entry_id):
    if not session.get('logged_in'):
        abort(403, description="Full authentication required")

    payload = request.get_json(silent=True) or {}
    action_id = clean_client_action_id(payload.get('client_action_id'))
    username = require_user()
    try:
        if action_id:
            completed, _ = get_completed_client_action(username, action_id)
            if completed:
                return jsonify({'ok': True, 'duplicate': True, 'split_id': split_id, 'entry_id': entry_id})

        split_doc = splits_collection(username).document(split_id).get()
        if not split_doc.exists:
            app.logger.warning("Split entry API delete requested for missing split=%s entry=%s user=%s", split_id, entry_id, username)
            return jsonify({'ok': False, 'error': 'Split not found.'}), 404

        entry_ref = split_entries_collection(split_id, username).document(entry_id)
        if not entry_ref.get().exists:
            app.logger.warning("Split entry API delete requested for missing entry split=%s entry=%s user=%s", split_id, entry_id, username)
            return jsonify({'ok': False, 'error': 'Split entry not found.'}), 404

        entry_ref.delete()
        splits_collection(username).document(split_id).set({'updated_at': datetime.now(UTC)}, merge=True)

        if action_id:
            save_completed_client_action(
                username,
                action_id,
                'split_entry_delete',
                {'split_id': split_id, 'entry_id': entry_id},
            )

        app.logger.info("Split entry API delete split=%s entry=%s user=%s", split_id, entry_id, username)
        return jsonify({
            'ok': True,
            'duplicate': False,
            'split_id': split_id,
            'entry_id': entry_id,
            'split': build_split_summary(doc_to_txn(split_doc), username=username),
        })
    except Exception:
        app.logger.exception("Split entry API delete failed split=%s entry=%s", split_id, entry_id)
        return jsonify({'ok': False, 'error': 'Failed to delete split entry.'}), 500


@app.route('/api/splits', methods=['GET'])
@login_required
def api_splits_list():
    username = require_user()
    try:
        splits = get_split_documents(username=username)
        live_split = get_live_split(username=username)

        # Serialize splits
        serialized_splits = []
        for s in splits:
            sid = s.get('id') or s.get('_id')
            serialized_splits.append({
                'id': sid,
                'title': s.get('title') or 'Untitled split',
                'is_live': bool(s.get('is_live')),
                'updated_at': format_ist(s.get('updated_at')) if s.get('updated_at') else None
            })

        serialized_live = None
        if live_split:
            serialized_live = {
                'id': live_split.get('id') or live_split.get('_id'),
                'title': live_split.get('title') or 'Untitled split',
                'is_live': True,
                'updated_at': format_ist(live_split.get('updated_at')) if live_split.get('updated_at') else None
            }

        app.logger.info("API Splits requested user=%s count=%d", username, len(serialized_splits))
        return jsonify({
            'ok': True,
            'splits': serialized_splits,
            'live_split': serialized_live
        })
    except Exception as e:
        app.logger.exception("Failed to fetch splits list API for user=%s", username)
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/splits/<string:split_id>/summary')
@login_required
def api_split_summary(split_id):
    username = require_user()
    split_doc = splits_collection(username).document(split_id).get()
    if not split_doc.exists:
        return jsonify({'ok': False, 'error': 'Split not found'}), 404
    return jsonify({'ok': True, 'split': build_split_summary(doc_to_txn(split_doc), username=username)})


# ---------------------------------------------------------------------
# Trips Routes (Create, Edit, Delete, Disconnect)
# ---------------------------------------------------------------------

@app.route('/trips', methods=['GET', 'POST'])
@login_required
def trips():
    username = require_user()
    form = TripForm()
    if session.get('view_only'):
        form = TripForm(formdata=None)

    if not session.get('view_only') and request.method == 'POST':
        # JSON API payload check (offline sync)
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            name = validate_short_text(payload.get('name'), 'Trip Name')
            start_date_str = payload.get('start_date')
            end_date_str = payload.get('end_date')
            description = validate_short_text(payload.get('description'), 'Description', max_len=500) or ''
            photo_link = validate_short_text(payload.get('photo_link'), 'Photos Link', max_len=255) or ''
            cost_type = payload.get('cost_type', 'fixed')
            approx_cost_val = float(payload.get('approx_cost') or 0.0)

            # Date conversions
            try:
                start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
                end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
            except Exception:
                return jsonify({'ok': False, 'error': 'Invalid date format (use YYYY-MM-DD)'}), 400

            split_id = None
            if cost_type == 'split':
                # Automatically create a new Split document
                split_doc = {
                    'title': name,
                    'is_live': False,
                    'created_at': datetime.now(UTC),
                    'updated_at': datetime.now(UTC),
                }
                split_ref = splits_collection(username).document()
                split_ref.set(split_doc)
                split_id = split_ref.id
                approx_cost_val = 0.0

            trip_doc = {
                'name': name,
                'start_date': local_datetime_to_utc(start_date, datetime.min.time()),
                'end_date': local_datetime_to_utc(end_date, datetime.max.time().replace(second=0, microsecond=0)),
                'description': description,
                'photo_link': photo_link,
                'cost_type': cost_type,
                'approx_cost': approx_cost_val,
                'split_id': split_id,
                'created_at': datetime.now(UTC),
                'updated_at': datetime.now(UTC),
            }
            doc_ref = trips_collection(username).document()
            doc_ref.set(trip_doc)
            app.logger.info("Trip created via JSON id=%s user=%s cost_type=%s", doc_ref.id, username, cost_type)
            return jsonify({'ok': True, 'id': doc_ref.id})

        if form.validate_on_submit():
            name = form.name.data
            start_date = form.start_date.data
            end_date = form.end_date.data
            description = form.description.data or ''
            photo_link = form.photo_link.data or ''
            cost_type = form.cost_type.data
            approx_cost_val = float(form.approx_cost.data or 0.0)

            split_id = None
            if cost_type == 'split':
                split_doc = {
                    'title': name,
                    'is_live': False,
                    'created_at': datetime.now(UTC),
                    'updated_at': datetime.now(UTC),
                }
                split_ref = splits_collection(username).document()
                split_ref.set(split_doc)
                split_id = split_ref.id
                approx_cost_val = 0.0

            trip_doc = {
                'name': name,
                'start_date': local_datetime_to_utc(start_date, datetime.min.time()),
                'end_date': local_datetime_to_utc(end_date, datetime.max.time().replace(second=0, microsecond=0)),
                'description': description,
                'photo_link': photo_link,
                'cost_type': cost_type,
                'approx_cost': approx_cost_val,
                'split_id': split_id,
                'created_at': datetime.now(UTC),
                'updated_at': datetime.now(UTC),
            }
            doc_ref = trips_collection(username).document()
            doc_ref.set(trip_doc)
            app.logger.info("Trip created id=%s user=%s cost_type=%s", doc_ref.id, username, cost_type)
            flash('Trip created successfully.', 'success')
            return redirect(url_for('trips'))
        else:
            app.logger.warning("Trip validation failed user=%s errors=%s", username, form.errors)
            for fieldName, errorMessages in form.errors.items():
                for err in errorMessages:
                    flash(f"{form[fieldName].label.text}: {err}", "danger")
            return redirect(url_for('trips'))

    # GET request
    trips_list = get_trip_documents(username=username)
    splits_list = get_split_documents(username=username)
    return render_template(
        'trips.html',
        form=form,
        trips=trips_list,
        splits=splits_list,
    )


@app.route('/trips/edit/<string:trip_id>', methods=['POST'])
@login_required
def trip_edit(trip_id):
    if session.get('view_only'):
        abort(401, description="View-only sessions cannot edit trips")
    username = require_user()
    doc_ref = trips_collection(username).document(trip_id)
    doc = doc_ref.get()
    if not doc.exists:
        flash('Trip not found.', 'warning')
        return redirect(url_for('trips'))

    existing = doc_to_txn(doc)

    if request.is_json:
        payload = request.get_json(silent=True) or {}
        name = validate_short_text(payload.get('name'), 'Trip Name')
        start_date_str = payload.get('start_date')
        end_date_str = payload.get('end_date')
        description = validate_short_text(payload.get('description'), 'Description', max_len=500) or ''
        photo_link = validate_short_text(payload.get('photo_link'), 'Photos Link', max_len=255) or ''
        cost_type = payload.get('cost_type', 'fixed')
        approx_cost_val = float(payload.get('approx_cost') or 0.0)

        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        except Exception:
            return jsonify({'ok': False, 'error': 'Invalid date format (use YYYY-MM-DD)'}), 400

        split_id = existing.get('split_id')
        if cost_type == 'split' and not split_id:
            split_doc = {
                'title': name,
                'is_live': False,
                'created_at': datetime.now(UTC),
                'updated_at': datetime.now(UTC),
            }
            split_ref = splits_collection(username).document()
            split_ref.set(split_doc)
            split_id = split_ref.id
            approx_cost_val = 0.0
        elif cost_type == 'fixed' and split_id:
            split_id = None

        update_doc = {
            'name': name,
            'start_date': local_datetime_to_utc(start_date, datetime.min.time()),
            'end_date': local_datetime_to_utc(end_date, datetime.max.time().replace(second=0, microsecond=0)),
            'description': description,
            'photo_link': photo_link,
            'cost_type': cost_type,
            'approx_cost': approx_cost_val,
            'split_id': split_id,
            'updated_at': datetime.now(UTC),
        }
        doc_ref.set(update_doc, merge=True)
        app.logger.info("Trip edited via JSON id=%s user=%s", trip_id, username)
        return jsonify({'ok': True})

    form = TripForm()
    if form.validate_on_submit():
        name = form.name.data
        start_date = form.start_date.data
        end_date = form.end_date.data
        description = form.description.data or ''
        photo_link = form.photo_link.data or ''
        cost_type = form.cost_type.data
        approx_cost_val = float(form.approx_cost.data or 0.0)

        split_id = existing.get('split_id')
        if cost_type == 'split' and not split_id:
            split_doc = {
                'title': name,
                'is_live': False,
                'created_at': datetime.now(UTC),
                'updated_at': datetime.now(UTC),
            }
            split_ref = splits_collection(username).document()
            split_ref.set(split_doc)
            split_id = split_ref.id
            approx_cost_val = 0.0
        elif cost_type == 'fixed' and split_id:
            split_id = None

        update_doc = {
            'name': name,
            'start_date': local_datetime_to_utc(start_date, datetime.min.time()),
            'end_date': local_datetime_to_utc(end_date, datetime.max.time().replace(second=0, microsecond=0)),
            'description': description,
            'photo_link': photo_link,
            'cost_type': cost_type,
            'approx_cost': approx_cost_val,
            'split_id': split_id,
            'updated_at': datetime.now(UTC),
        }
        doc_ref.set(update_doc, merge=True)
        app.logger.info("Trip edited id=%s user=%s", trip_id, username)
        flash('Trip updated successfully.', 'success')
    else:
        app.logger.warning("Trip edit validation failed user=%s errors=%s", username, form.errors)
        for fieldName, errorMessages in form.errors.items():
            for err in errorMessages:
                flash(f"{form[fieldName].label.text}: {err}", "danger")

    return redirect(url_for('trips'))


@app.route('/trips/delete/<string:trip_id>', methods=['POST'])
@login_required
def trip_delete(trip_id):
    if session.get('view_only'):
        abort(401, description="View-only sessions cannot delete trips")
    username = require_user()
    doc_ref = trips_collection(username).document(trip_id)
    if not doc_ref.get().exists:
        flash('Trip not found.', 'warning')
        return redirect(url_for('trips'))

    doc_ref.delete()
    app.logger.info("Trip deleted id=%s user=%s", trip_id, username)

    if request.is_json:
        return jsonify({'ok': True})

    flash('Trip deleted.', 'info')
    return redirect(url_for('trips'))


@app.route('/trips/disconnect/<string:trip_id>', methods=['POST'])
@login_required
def trip_disconnect(trip_id):
    if session.get('view_only'):
        abort(401, description="View-only sessions cannot disconnect split")
    username = require_user()
    doc_ref = trips_collection(username).document(trip_id)
    trip = doc_ref.get()
    if not trip.exists:
        if request.is_json:
            return jsonify({'ok': False, 'error': 'Trip not found'}), 404
        flash('Trip not found.', 'warning')
        return redirect(url_for('trips'))

    t = doc_to_txn(trip)
    split_id = t.get('split_id')

    # Get action: 'delete' or 'keep'
    action = 'keep'
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        action = payload.get('action', 'keep')
    else:
        action = request.form.get('action', 'keep')

    if split_id:
        if action == 'delete':
            # Delete connected split entries and split itself
            for entry in stream_with_timeout(split_entries_collection(split_id, username)):
                split_entries_collection(split_id, username).document(entry.id).delete()
            splits_collection(username).document(split_id).delete()
            app.logger.info("Split deleted during disconnect split_id=%s user=%s", split_id, username)
            flash('Connected split deleted successfully.', 'info')
        else:
            flash('Split disconnected successfully.', 'info')

    # Update trip to be fixed cost and clear split_id
    doc_ref.set({
        'split_id': None,
        'cost_type': 'fixed',
        'updated_at': datetime.now(UTC)
    }, merge=True)

    app.logger.info("Trip disconnected split_id=%s trip_id=%s action=%s user=%s", split_id, trip_id, action, username)

    if request.is_json:
        return jsonify({'ok': True})

    return redirect(url_for('trips'))


@app.route('/splits/disconnect/<string:split_id>', methods=['POST'])
@login_required
def split_disconnect_trip(split_id):
    if session.get('view_only'):
        abort(401, description="View-only sessions cannot disconnect trip")
    username = require_user()

    # Get action: 'delete' or 'keep'
    action = 'keep'
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        action = payload.get('action', 'keep')
    else:
        action = request.form.get('action', 'keep')

    # Find the trip connected to this split
    docs = stream_with_timeout(trips_collection(username).where('split_id', '==', split_id))
    trips_found = [doc_to_txn(doc) for doc in docs]

    for t in trips_found:
        trip_id = t.get('_id') or t.get('id')
        if action == 'delete':
            # Delete the trip
            trips_collection(username).document(trip_id).delete()
            app.logger.info("Trip deleted during split disconnect trip_id=%s user=%s", trip_id, username)
        else:
            # Clear split_id and change cost_type to fixed
            trips_collection(username).document(trip_id).set({
                'split_id': None,
                'cost_type': 'fixed',
                'updated_at': datetime.now(UTC)
            }, merge=True)
            app.logger.info("Trip disconnected during split disconnect trip_id=%s user=%s", trip_id, username)

    if action == 'delete':
        flash('Connected trip deleted successfully.', 'info')
    else:
        flash('Trip disconnected successfully.', 'info')

    if request.is_json:
        return jsonify({'ok': True})

    return redirect(url_for('splits'))


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
    user_entry = load_user_auth_from_store(username)
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

def copy_user_splits(old_user_ref, new_user_ref):
    docs = list(old_user_ref.collection('splits').stream(
        retry=None,
        timeout=FIRESTORE_TIMEOUT_SECONDS,
    ))
    copied = []
    for doc in docs:
        new_split_ref = new_user_ref.collection('splits').document(doc.id)
        new_split_ref.set(doc.to_dict() or {})
        copied.append(('splits', doc.id))
        entries = list(doc.reference.collection('entries').stream(
            retry=None,
            timeout=FIRESTORE_TIMEOUT_SECONDS,
        ))
        for entry in entries:
            new_split_ref.collection('entries').document(entry.id).set(entry.to_dict() or {})
            copied.append((f'splits/{doc.id}/entries', entry.id))
    return copied


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
    for collection_name in ('transactions', 'recurring', 'recurring_balances', 'balances', CLIENT_ACTIONS_COL):
        for doc in copy_user_subcollection(old_ref, new_ref, collection_name):
            copied_docs.append((collection_name, doc.id))
    copied_docs.extend(copy_user_splits(old_ref, new_ref))

    for collection_name, doc_id in copied_docs:
        if collection_name.startswith('splits/') and collection_name.endswith('/entries'):
            split_id = collection_name.split('/')[1]
            old_ref.collection('splits').document(split_id).collection('entries').document(doc_id).delete()
        else:
            old_ref.collection(collection_name).document(doc_id).delete()
    old_ref.delete()


@app.route('/management', methods=['GET', 'POST'])
@login_required
def management():
    username = require_user()
    form = ViewPasswordForm(prefix='view_password')
    reveal_form = ViewPasswordRevealForm(prefix='reveal_view_password')
    category_form = CategoryForm(prefix='category')
    split_person_form = SplitPersonForm(prefix='split_person')
    username_form = ChangeUsernameForm(prefix='account_username')
    password_form = ChangePasswordForm(prefix='account_password')
    categories = get_categories()
    split_people = get_split_people()

    if request.method == 'POST' and request.is_json:
        payload = request.get_json(silent=True) or {}
        json_action = payload.get('action')
        if json_action == 'add_category':
            new_category = normalize_category_name(payload.get('name'))
            if not new_category:
                return jsonify({'ok': False, 'error': 'Name is required'}), 400
            if category_exists(categories, new_category):
                return jsonify({'ok': False, 'error': 'Category already exists.'}), 400
            save_categories([*categories, new_category], updated_by=username)
            app.logger.info("Category added via JSON name=%s user=%s", new_category, username)
            return jsonify({'ok': True})
        if json_action == 'add_split_person':
            new_person = normalize_person_name(payload.get('name'))
            if not new_person:
                return jsonify({'ok': False, 'error': 'Name is required'}), 400
            if person_exists(split_people, new_person):
                return jsonify({'ok': False, 'error': 'Person already exists.'}), 400
            save_split_people([*split_people, new_person], updated_by=username)
            app.logger.info("Split person added via JSON name=%s user=%s", new_person, username)
            return jsonify({'ok': True})

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
                split_person_form=split_person_form,
                split_people=split_people,
                username_form=username_form,
                password_form=password_form,
            )
        flash('Current view-only password is incorrect.', 'danger')

    if action == 'add_category' and request.method == 'POST':
        if category_form.validate_on_submit():
            new_category = normalize_category_name(category_form.name.data)
            if category_exists(categories, new_category):
                flash('Category already exists.', 'warning')
                return redirect(url_for('management', add_category='true'))
            else:
                save_categories([*categories, new_category], updated_by=username)
                app.logger.info("Category added name=%s user=%s", new_category, username)
                flash('Category added successfully.', 'success')
                return redirect(url_for('management'))
        else:
            for fieldName, errorMessages in category_form.errors.items():
                for err in errorMessages:
                    flash(f"{category_form[fieldName].label.text}: {err}", "danger")
            return redirect(url_for('management', add_category='true'))

    if action == 'add_split_person' and request.method == 'POST':
        if split_person_form.validate_on_submit():
            new_person = normalize_person_name(split_person_form.name.data)
            if person_exists(split_people, new_person):
                flash('Person already exists.', 'warning')
                return redirect(url_for('management', add_person='true'))
            else:
                save_split_people([*split_people, new_person], updated_by=username)
                app.logger.info("Split person added name=%s user=%s", new_person, username)
                flash('Person added successfully.', 'success')
                return redirect(url_for('management'))
        else:
            for fieldName, errorMessages in split_person_form.errors.items():
                for err in errorMessages:
                    flash(f"{split_person_form[fieldName].label.text}: {err}", "danger")
            return redirect(url_for('management', add_person='true'))

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
        'add_split_person',
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
        split_person_form=split_person_form,
        split_people=split_people,
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

    if request.is_json:
        payload = request.get_json(silent=True) or {}
        updated = normalize_category_name(payload.get('name'))
        if not updated:
            return jsonify({'ok': False, 'error': 'Name is required'}), 400
        if category_key(updated) != category_key(original) and category_exists(categories, updated):
            return jsonify({'ok': False, 'error': 'Category already exists.'}), 400
        renamed = [updated if category_key(item) == category_key(original) else item for item in categories]
        save_categories(renamed, updated_by=username)
        app.logger.info("Category renamed via JSON old=%s new=%s user=%s", original, updated, username)
        return jsonify({'ok': True})

    if category_form.validate_on_submit():
        updated = normalize_category_name(category_form.name.data)
        if category_key(updated) != category_key(original) and category_exists(categories, updated):
            flash('Category already exists.', 'warning')
            return redirect(url_for('management', edit='true', edit_id=original))

        renamed = [updated if category_key(item) == category_key(original) else item for item in categories]
        save_categories(renamed, updated_by=username)
        app.logger.info("Category renamed old=%s new=%s user=%s", original, updated, username)
        flash('Category updated.', 'success')
        return redirect(url_for('management'))

    if request.method == 'GET':
        return redirect(url_for('management', edit='true', edit_id=original))

    # POST validation failed
    for fieldName, errorMessages in category_form.errors.items():
        for err in errorMessages:
            flash(f"{category_form[fieldName].label.text}: {err}", "danger")
    return redirect(url_for('management', edit='true', edit_id=original))


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

    if request.is_json:
        save_categories(remaining, updated_by=username)
        app.logger.info("Category deleted via JSON name=%s user=%s", category, username)
        return jsonify({'ok': True})

    save_categories(remaining, updated_by=username)
    app.logger.info("Category deleted name=%s user=%s", category, username)
    flash('Category deleted.', 'info')
    return redirect(url_for('management'))


@app.route('/management/split-people/edit/<path:person_name>', methods=['GET', 'POST'])
@login_required
def management_split_person_edit(person_name):
    username = require_user()
    original = normalize_person_name(person_name)
    split_people = get_split_people()
    split_person_form = SplitPersonForm(prefix='split_person')
    split_person_form.submit.label.text = 'Update Person'

    if not person_exists(split_people, original):
        flash('Person not found.', 'warning')
        return redirect(url_for('management'))

    if request.is_json:
        payload = request.get_json(silent=True) or {}
        updated = normalize_person_name(payload.get('name'))
        if not updated:
            return jsonify({'ok': False, 'error': 'Name is required'}), 400
        if person_key(updated) != person_key(original) and person_exists(split_people, updated):
            return jsonify({'ok': False, 'error': 'Person already exists.'}), 400
        renamed = [updated if person_key(item) == person_key(original) else item for item in split_people]
        save_split_people(renamed, updated_by=username)
        app.logger.info("Split person renamed via JSON old=%s new=%s user=%s", original, updated, username)
        return jsonify({'ok': True})

    if split_person_form.validate_on_submit():
        updated = normalize_person_name(split_person_form.name.data)
        if person_key(updated) != person_key(original) and person_exists(split_people, updated):
            flash('Person already exists.', 'warning')
            return redirect(url_for('management', edit_person='true', edit_id=original))

        renamed = [updated if person_key(item) == person_key(original) else item for item in split_people]
        save_split_people(renamed, updated_by=username)
        app.logger.info("Split person renamed old=%s new=%s user=%s", original, updated, username)
        flash('Person updated.', 'success')
        return redirect(url_for('management'))

    if request.method == 'GET':
        return redirect(url_for('management', edit_person='true', edit_id=original))

    # POST validation failed
    for fieldName, errorMessages in split_person_form.errors.items():
        for err in errorMessages:
            flash(f"{split_person_form[fieldName].label.text}: {err}", "danger")
    return redirect(url_for('management', edit_person='true', edit_id=original))


@app.route('/management/split-people/delete/<path:person_name>', methods=['POST'])
@login_required
def management_split_person_delete(person_name):
    username = require_user()
    person = normalize_person_name(person_name)
    split_people = get_split_people()
    remaining = [item for item in split_people if person_key(item) != person_key(person)]

    if len(remaining) == len(split_people):
        flash('Person not found.', 'warning')
        return redirect(url_for('management'))

    if not remaining:
        flash('At least one person is required.', 'warning')
        return redirect(url_for('management'))

    if request.is_json:
        save_split_people(remaining, updated_by=username)
        app.logger.info("Split person deleted via JSON name=%s user=%s", person, username)
        return jsonify({'ok': True})

    save_split_people(remaining, updated_by=username)
    app.logger.info("Split person deleted name=%s user=%s", person, username)
    flash('Person deleted.', 'info')
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

        try:
            user_entry, auth_source = get_user_auth_for_login(username)
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
                app.logger.info("User %s logged in (full session, auth_source=%s)", username, auth_source)
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
        user_entry, auth_source = get_user_auth_for_login(username)
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
            app.logger.info("User %s logged in (full session) via /view auth_source=%s", username, auth_source)
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


@app.route('/api/login_offline', methods=['POST'])
def api_login_offline():
    payload = request.get_json(silent=True) or {}
    username = normalize_username(payload.get('username'))
    login_type = payload.get('type')

    if not username:
        return jsonify({'ok': False, 'error': 'Username is required.'}), 400

    session.permanent = True
    session['username'] = username
    if login_type == 'view':
        session['view_only'] = True
        session.pop('logged_in', None)
        app.logger.info("Offline view-only session granted for user=%s", username)
    else:
        session['logged_in'] = True
        session.pop('view_only', None)
        app.logger.info("Offline full session granted for user=%s", username)

    return jsonify({'ok': True})


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

def append_balance(delta, type_, note='', username=None, extra_fields=None):
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
    if extra_fields:
        doc.update(extra_fields)
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

@app.route('/balance/analytics')
@login_required
def balance_analytics():
    return render_template('balance_analytics.html')

@app.route('/api/balance_current')
@login_required
def api_balance_current():
    username = require_user()
    latest = get_latest_balance(username=username)
    q = (
        bal_collection(username)
        .order_by('timestamp', direction=firestore.Query.DESCENDING)
        .limit(100)
    )
    raw_docs = [doc_to_txn(d) for d in stream_with_timeout(q)]
    docs = [d for d in raw_docs if d.get('type') not in ('txn', 'transaction')][:BALANCE_HISTORY_TABLE_LIMIT]
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

def _generate_period_labels(start_dt, end_dt, period):
    if period == 'daily':
        cur_date = utc_to_ist(start_dt).date()
        endd = utc_to_ist(end_dt).date()
        return [(cur_date + relativedelta(days=i)).isoformat() for i in range((endd - cur_date).days + 1)]

    if period == 'monthly':
        start_local = utc_to_ist(start_dt)
        end_local = utc_to_ist(end_dt)
        cur = date(start_local.year, start_local.month, 1)
        endm = date(end_local.year, end_local.month, 1)
        months = []
        while cur <= endm:
            months.append(cur)
            cur += relativedelta(months=1)
        return [m.strftime('%Y-%m') for m in months]

    if period == 'yearly':
        return [str(y) for y in range(utc_to_ist(start_dt).year, utc_to_ist(end_dt).year + 1)]

    return []


def _balance_bucket_key(timestamp, period):
    if not timestamp:
        return None
    local = utc_to_ist(timestamp)
    if period == 'daily':
        return local.date().isoformat()
    if period == 'monthly':
        return local.strftime('%Y-%m')
    if period == 'yearly':
        return str(local.year)
    return None


def _build_balance_series_values(bal_docs, labels, period):
    bucket_last = {}
    for entry in bal_docs:
        key = _balance_bucket_key(entry.get('timestamp'), period)
        if key:
            bucket_last[key] = float(entry.get('balance', 0.0))

    last_known = None
    values = []
    for label in labels:
        if label in bucket_last:
            last_known = bucket_last[label]
        values.append(round(float(last_known or 0.0), 2))
    return values


def _build_delta_series_values(bal_docs, labels, period):
    bucket_sums = {label: 0.0 for label in labels}
    for entry in bal_docs:
        key = _balance_bucket_key(entry.get('timestamp'), period)
        if key in bucket_sums:
            bucket_sums[key] += float(entry.get('delta', 0.0))
    return [round(bucket_sums[label], 2) for label in labels]


def _balance_type_label(type_key):
    labels = {
        'add': 'Manual add',
        'sync': 'Sync',
        'txn': 'Transaction',
        'txn_edit': 'Edit transaction',
        'txn_delete': 'Delete transaction',
        'recurring': 'Recurring expense',
        'recurring_balance': 'Recurring balance',
    }
    key = str(type_key or '').strip()
    return labels.get(key, key.replace('_', ' ').title() or 'Other')


def _serialize_balance_entry(entry):
    return {
        'id': entry.get('_id'),
        'timestamp': format_ist(entry.get('timestamp')) if entry.get('timestamp') else None,
        'balance': round(float(entry.get('balance', 0.0)), 2),
        'type': entry.get('type'),
        'type_label': _balance_type_label(entry.get('type')),
        'delta': round(float(entry.get('delta', 0.0)), 2),
        'note': entry.get('note', ''),
    }


@app.route('/api/balance_series')
@login_required
def api_balance_series():
    start_dt, end_dt, period = _parse_period_args(request.args)
    bal_docs = get_balances_in_range(start_dt, end_dt, order_desc=False)
    labels = _generate_period_labels(start_dt, end_dt, period)
    if not labels:
        return jsonify({'labels': [], 'values': []})
    values = _build_balance_series_values(bal_docs, labels, period)
    return jsonify({'labels': labels, 'values': values})


@app.route('/api/balance_analytics')
@login_required
def api_balance_analytics():
    username = require_user()
    start_dt, end_dt, period = _parse_period_args(request.args)
    bal_docs = get_balances_in_range(start_dt, end_dt, order_desc=False, username=username)
    labels = _generate_period_labels(start_dt, end_dt, period)

    balance_values = _build_balance_series_values(bal_docs, labels, period) if labels else []
    delta_values = _build_delta_series_values(bal_docs, labels, period) if labels else []

    deltas = [float(entry.get('delta', 0.0)) for entry in bal_docs]
    net_change = round(sum(deltas), 2)
    count = len(deltas)
    avg_delta = round((sum(deltas) / count), 2) if count else 0.0
    min_delta = round(min(deltas), 2) if count else 0.0
    max_delta = round(max(deltas), 2) if count else 0.0
    median_delta = round(statistics.median(deltas), 2) if count else 0.0

    opening_balance = round(float(balance_values[0]), 2) if balance_values else 0.0
    closing_balance = round(float(balance_values[-1]), 2) if balance_values else 0.0

    latest = get_latest_balance(username=username)
    current_balance = round(float(latest.get('balance', 0.0)), 2) if latest else closing_balance

    period_duration = end_dt - start_dt
    prev_end = start_dt - relativedelta(seconds=1)
    prev_start = prev_end - period_duration
    prev_docs = get_balances_in_range(prev_start, prev_end, order_desc=False, username=username)
    prev_net = round(sum(float(entry.get('delta', 0.0)) for entry in prev_docs), 2)
    pct_change = None
    if prev_net != 0:
        pct_change = round(((net_change - prev_net) / abs(prev_net)) * 100.0, 2)

    type_stats = {}
    for entry in bal_docs:
        key = str(entry.get('type') or 'other')
        if key not in type_stats:
            type_stats[key] = {'type': key, 'label': _balance_type_label(key), 'count': 0, 'total_delta': 0.0}
        type_stats[key]['count'] += 1
        type_stats[key]['total_delta'] += float(entry.get('delta', 0.0))

    by_type = sorted(
        [
            {
                'type': item['type'],
                'label': item['label'],
                'count': item['count'],
                'total_delta': round(item['total_delta'], 2),
            }
            for item in type_stats.values()
        ],
        key=lambda row: abs(row['total_delta']),
        reverse=True,
    )

    largest_entry = None
    if bal_docs:
        largest = max(bal_docs, key=lambda row: abs(float(row.get('delta', 0.0))))
        largest_entry = {
            'delta': round(float(largest.get('delta', 0.0)), 2),
            'type_label': _balance_type_label(largest.get('type')),
            'timestamp': format_ist(largest.get('timestamp')) if largest.get('timestamp') else None,
        }

    top_type = by_type[0] if by_type else None

    entries = [_serialize_balance_entry(entry) for entry in reversed(bal_docs)]

    summary = {
        'current_balance': current_balance,
        'opening_balance': opening_balance,
        'closing_balance': closing_balance,
        'net_change': net_change,
        'count': count,
        'avg_delta': avg_delta,
        'min_delta': min_delta,
        'max_delta': max_delta,
        'median_delta': median_delta,
        'prev_net_change': prev_net,
        'pct_change': pct_change,
        'top_type': top_type,
        'largest_entry': largest_entry,
    }

    return jsonify({
        'labels': labels,
        'balance_values': balance_values,
        'delta_values': delta_values,
        'summary': summary,
        'by_type': by_type,
        'entries': entries,
    })

@app.route('/api/balance/add', methods=['POST'])
@login_required
def api_balance_add():
    username = require_user()
    data = request.get_json() or {}
    completed, action_id = get_completed_client_action(username, data.get('client_action_id'))
    if completed:
        result = completed.get('result') or {}
        result['duplicate'] = True
        return jsonify(result)

    try:
        delta = parse_money(data.get('amount'), field_name='Amount', allow_negative=True)
        note = validate_optional_note(data.get('note'))
    except ValueError as exc:
        app.logger.warning("Balance add validation failed user=%s error=%s", username, exc)
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
    result = {"balance": new_bal, "timestamp": format_ist(now), "type": "add", "duplicate": False}
    save_completed_client_action(username, action_id, 'balance_add', result)
    app.logger.info("Balance add created user=%s delta=%.2f new_balance=%.2f", username, delta, new_bal)
    return jsonify(result)

@app.route('/api/balance/sync', methods=['POST'])
@login_required
def api_balance_sync():
    username = require_user()
    data = request.get_json() or {}
    completed, action_id = get_completed_client_action(username, data.get('client_action_id'))
    if completed:
        result = completed.get('result') or {}
        result['duplicate'] = True
        return jsonify(result)

    try:
        new_balance = parse_money(
            data.get('balance'),
            field_name='Balance value',
            allow_zero=True,
            allow_negative=True,
        )
        note = validate_optional_note(data.get('note'))
    except ValueError as exc:
        app.logger.warning("Balance sync validation failed user=%s error=%s", username, exc)
        return jsonify({"error": str(exc)}), 400
    now = datetime.now(UTC)
    latest = get_latest_balance(username=username)
    base = float(latest.get('balance', 0.0)) if latest else 0.0
    delta = round(new_balance - base, 2)
    doc = {
        'balance': float(round(new_balance, 2)),
        'type': 'add',
        'delta': float(delta),
        'note': note,
        'timestamp': now
    }
    bal_collection(username).add(doc)
    result = {
        "balance": round(new_balance, 2),
        "timestamp": format_ist(now),
        "type": "add",
        "delta": delta,
        "duplicate": False,
    }
    save_completed_client_action(username, action_id, 'balance_sync', result)
    app.logger.info("Balance sync created user=%s delta=%.2f new_balance=%.2f", username, delta, new_balance)
    return jsonify(result)

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
        app.logger.warning("Balance update requested for missing entry id=%s user=%s", entry_id, username)
        return jsonify({"error": "Balance entry not found"}), 404

    entry = doc_to_txn(doc)
    entry_type = (entry.get('type') or '').lower()
    if entry_type not in {'add', 'sync'}:
        app.logger.warning("Balance update blocked for non-manual entry id=%s user=%s type=%s", entry_id, username, entry_type)
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
        app.logger.warning("Balance update validation failed id=%s user=%s error=%s", entry_id, username, exc)
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
    q = bal_collection(username).order_by('timestamp', direction=firestore.Query.DESCENDING).limit(200)
    raw_docs = [doc_to_txn(d) for d in stream_with_timeout(q)]
    docs = [d for d in raw_docs if d.get('type') not in ('txn', 'transaction')][:limit]
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




