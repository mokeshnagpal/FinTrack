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
    ForgotPasswordForm,
    VerifyOTPForm,
    ResetPasswordForm,
    STRONG_PASSWORD_PATTERN,
    STRONG_PASSWORD_MESSAGE,
)
from constants import (
    DEFAULT_RECURRING_THROTTLE_SECONDS,
)
import os
import io
import csv
import statistics
import re
import secrets
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import credentials, firestore
from types import SimpleNamespace
import logging
import json
import time
import math
import hashlib
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

DEFAULT_ADMIN_PASSWORD = os.environ.get('ADMIN_PASS')
if isinstance(DEFAULT_ADMIN_PASSWORD, str):
    DEFAULT_ADMIN_PASSWORD = DEFAULT_ADMIN_PASSWORD.strip()

DEFAULT_CATEGORY_ACCESS_RAW = os.environ.get('DEFAULT_CATEGORY_ACCESS', '')
DEFAULT_CATEGORY_ACCESS = {}
if isinstance(DEFAULT_CATEGORY_ACCESS_RAW, str) and DEFAULT_CATEGORY_ACCESS_RAW.strip():
    try:
        DEFAULT_CATEGORY_ACCESS = json.loads(DEFAULT_CATEGORY_ACCESS_RAW)
        if not isinstance(DEFAULT_CATEGORY_ACCESS, dict):
            DEFAULT_CATEGORY_ACCESS = {}
    except Exception:
        raw = DEFAULT_CATEGORY_ACCESS_RAW.strip()
        parts = [part.strip() for part in raw.split(',') if part.strip()]
        for part in parts:
            if ':' in part:
                key, value = part.split(':', 1)
                DEFAULT_CATEGORY_ACCESS[key.strip()] = value.strip().lower()

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

RECURRING_THROTTLE_SECONDS = env_int('RECURRING_THROTTLE_SECONDS', DEFAULT_RECURRING_THROTTLE_SECONDS)
FIRESTORE_TIMEOUT_SECONDS = env_int('FIRESTORE_TIMEOUT_SECONDS', 8)
ENABLE_DEBUG_ROUTES = env_bool('ENABLE_DEBUG_ROUTES', False)
MAX_MONEY_AMOUNT = 999999999
MAX_DESCRIPTION_LENGTH = 120
MAX_NOTE_LENGTH = 120

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
            'balance_history_table_limit': 12,
            'recurring_rule_table_limit': 12,
            'split_document_table_limit': 12,
            'split_entry_table_limit': 12,
            'transaction_page_size': 12,
        }
    }

# ---------------------------------------------------------------------
# Utilities: timestamp parsing & document conversion
# ---------------------------------------------------------------------
ADMIN_USER_RAW = os.environ.get('ADMIN_USER', '')
ADMIN_USERS = set(u.strip().lower() for u in ADMIN_USER_RAW.split(',') if u.strip())

def is_env_admin(username):
    return normalize_username(username) in ADMIN_USERS

VIEW_ONLY_ALLOWED_PREFIXES = (
    '/balance',
    '/balance/analytics',
    '/analytics',
    '/transactions',
    '/trips',
    '/splits',
    '/api/balance_current',
    '/api/balance_series',
    '/api/balance_analytics',
    '/api/splits',
    '/api/totals',
    '/api/category_breakdown',
    '/api/transactions_range',
    '/export/transactions_csv',
    '/export/balances_csv',
    '/export/all_data_zip',
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

def saved_transaction_collection(username=None):
    return user_doc_ref(username).collection('saved_tranaction')

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


def get_user_details(username):
    normalized = normalize_username(username)
    if not normalized:
        return {}
    try:
        doc = user_doc_ref(normalized).get(
            retry=None,
            timeout=FIRESTORE_TIMEOUT_SECONDS,
        )
        if doc.exists:
            return doc.to_dict() or {}
    except Exception:
        app.logger.exception("Failed to load user details for %s", normalized)
    return {}

def get_user_view_pass_hash(username):
    return (get_user_details(username) or {}).get('view_pass') or ''

def get_user_admin_pass_hash(username):
    return (get_user_details(username) or {}).get('admin_pass') or ''

def get_user_auth_password_hash(user_data):
    return (user_data.get('admin_pass') or user_data.get('password') or '')


def get_default_category_access():
    if DEFAULT_CATEGORY_ACCESS:
        return DEFAULT_CATEGORY_ACCESS

    categories = default_categories()
    return {
        item: 'protected' if item.lower() == 'trip' else 'public'
        for item in categories
    }


def ensure_user_document_structure(username, user_data):
    normalized = normalize_username(username)
    if not normalized or not user_data:
        return

    update_payload = {}
    existing_admin_hash = user_data.get('admin_pass')
    existing_password_hash = user_data.get('password')

    if not existing_admin_hash and existing_password_hash:
        update_payload['admin_pass'] = existing_password_hash
        update_payload['view_pass'] = existing_password_hash
        update_payload['password'] = firestore.DELETE_FIELD

    if not user_data.get('view_pass'):
        admin_hash = existing_admin_hash or update_payload.get('admin_pass')
        if admin_hash:
            update_payload['view_pass'] = admin_hash

    categories_value = user_data.get('categories')
    categories_map = None
    if isinstance(categories_value, dict):
        categories_map = {
            normalize_category_name(key): normalize_category_access(value)
            for key, value in categories_value.items()
            if normalize_category_name(key)
        }
        if categories_map != categories_value:
            update_payload['categories'] = categories_map
    elif isinstance(categories_value, list):
        categories_map = {
            item: 'protected' if item.lower() == 'trip' else 'public'
            for item in categories_value
            if normalize_category_name(item)
        }
        update_payload['categories'] = categories_map
    else:
        categories_map = get_default_category_access()
        update_payload['categories'] = categories_map

    default_category_value = user_data.get('default_category')
    if not isinstance(default_category_value, str) or not category_exists(categories_map.keys(), default_category_value):
        update_payload['default_category'] = next(iter(categories_map.keys()), 'Other')

    if update_payload:
        fs.collection('users').document(normalized).update(update_payload)


def set_user_passes(username, view_pass_hash=None, admin_pass_hash=None):
    normalized = normalize_username(username)
    if not normalized:
        return
    payload = {}
    if view_pass_hash is not None:
        payload['view_pass'] = view_pass_hash
    if admin_pass_hash is not None:
        payload['admin_pass'] = admin_pass_hash
    if payload:
        user_doc_ref(normalized).set(payload, merge=True)


def normalize_category_access(value):
    return 'protected' if str(value or '').strip().lower() == 'protected' else 'public'


def load_user_categories_from_store(username=None):
    username = normalize_username(username or get_current_username() or '')
    if username:
        try:
            doc = user_doc_ref(username).get(
                retry=None,
                timeout=FIRESTORE_TIMEOUT_SECONDS,
            )
            if doc.exists:
                data = doc.to_dict() or {}
                raw_categories = data.get('categories')
                categories = {}
                if isinstance(raw_categories, dict):
                    for key, access in raw_categories.items():
                        name = normalize_category_name(key)
                        if not name:
                            continue
                        categories[name] = normalize_category_access(access)
                elif isinstance(raw_categories, list):
                    for item in raw_categories:
                        name = normalize_category_name(item)
                        if not name:
                            continue
                        categories[name] = 'protected' if name.lower() == 'trip' else 'public'

                default_cat = normalize_category_name(data.get('default_category')) or 'Other'
                if not categories:
                    categories = get_default_category_access()
                if not category_exists(list(categories.keys()), default_cat):
                    default_cat = next(iter(categories.keys()), 'Other')
                return categories, default_cat
        except Exception:
            app.logger.exception("Failed to load user categories for %s", username)

    fallback_categories = get_default_category_access()
    return fallback_categories, next(iter(fallback_categories.keys()), 'Other')


def get_default_category_access():
    if DEFAULT_CATEGORY_ACCESS:
        return DEFAULT_CATEGORY_ACCESS

    categories = default_categories()
    return {
        item: 'protected' if item.lower() == 'trip' else 'public'
        for item in categories
    }


def get_categories(username=None):
    categories, _ = load_user_categories_from_store(username)
    return list(categories.keys())


def get_default_category(username=None):
    categories, default_cat = load_user_categories_from_store(username)
    if default_cat and category_exists(categories.keys(), default_cat):
        return default_cat
    return 'Other'


def save_user_categories(username, categories, default_category=None, updated_by=None):
    normalized_username = normalize_username(username)
    if not normalized_username:
        return []

    category_map = {}
    if isinstance(categories, dict):
        for key, access in categories.items():
            name = normalize_category_name(key)
            if not name:
                continue
            category_map[name] = normalize_category_access(access)
    else:
        for item in categories:
            name = normalize_category_name(item)
            if not name:
                continue
            category_map[name] = 'protected' if name.lower() == 'trip' else 'public'

    if not category_map:
        category_map = {'Other': 'public'}

    payload = {
        'categories': category_map,
    }
    if updated_by:
        payload['updated_by'] = updated_by
    if default_category:
        payload['default_category'] = normalize_category_name(default_category)
    elif not category_exists(category_map.keys(), get_default_category(username)):
        payload['default_category'] = next(iter(category_map.keys()), 'Other')

    try:
        user_doc_ref(username).set(payload, merge=True)
    except Exception:
        app.logger.exception("Failed to save user categories for %s", username)

    return list(category_map.keys())


def get_category_access(category, username=None):
    categories, _ = load_user_categories_from_store(username)
    for key, access in categories.items():
        if category_key(key) == category_key(category):
            return access
    return 'public'


def category_is_protected(category, username=None):
    if category_key(category) in {'uncategorized', 'trip'}:
        return True
    return get_category_access(category, username) == 'protected'


def save_categories(categories, updated_by=None):
    username = get_current_username()
    if not username:
        return []
    return save_user_categories(username, categories, default_category=get_default_category(username), updated_by=updated_by)


def bootstrap_view_only_password_from_env_for_user(username):
    if not HW_PASSWORD:
        return
    if get_user_view_pass_hash(username):
        return
    set_user_passes(username, view_pass_hash=make_password_hash(HW_PASSWORD))
    app.logger.info("Bootstrapped view-only password into user document for %s", normalize_username(username))


def get_view_only_password_hash(username=None):
    try:
        if username:
            return get_user_view_pass_hash(username) or None
        # if no username provided, return None (per-user storage preferred)
        return None
    except Exception:
        app.logger.exception("Failed to load view-only password configuration")
        return None

def load_categories_from_store():
    return default_categories(), 'Other'

def load_user_auth_from_store(username):
    normalized_username = normalize_username(username)
    if not normalized_username:
        return {'exists': False, 'data': {}}

    doc = fs.collection('users').document(normalized_username).get(
        retry=None,
        timeout=FIRESTORE_TIMEOUT_SECONDS,
    )
    if not doc.exists:
        return freeze_user_auth_entry({'exists': False, 'data': {}})

    data = doc.to_dict() or {}
    try:
        ensure_user_document_structure(normalized_username, data)
    except Exception:
        app.logger.exception("Failed to migrate user document structure for %s", normalized_username)

    return freeze_user_auth_entry({
        'exists': True,
        'data': data,
    })

def bootstrap_env_admin_user(username, password=None, source='env_admin'):
    normalized_username = normalize_username(username)
    if not normalized_username or normalized_username not in ADMIN_USERS:
        return {'exists': False, 'data': {}}

    user_ref = fs.collection('users').document(normalized_username)
    existing_doc = user_ref.get(
        retry=None,
        timeout=FIRESTORE_TIMEOUT_SECONDS,
    )
    if existing_doc.exists:
        existing_data = existing_doc.to_dict() or {}
        now = datetime.now(UTC)
        update_payload = {}

        if not existing_data.get('admin_pass'):
            if DEFAULT_ADMIN_PASSWORD:
                update_payload['admin_pass'] = make_password_hash(DEFAULT_ADMIN_PASSWORD)
                update_payload['bootstrap_source'] = source

        if not existing_data.get('view_pass'):
            if HW_PASSWORD:
                update_payload['view_pass'] = make_password_hash(HW_PASSWORD)
            elif update_payload.get('admin_pass'):
                update_payload['view_pass'] = update_payload['admin_pass']

        categories_value = existing_data.get('categories')
        if isinstance(categories_value, list):
            update_payload['categories'] = {
                item: 'protected' if item.lower() == 'trip' else 'public'
                for item in categories_value
            }
        elif isinstance(categories_value, dict):
            update_payload['categories'] = {
                normalize_category_name(key): normalize_category_access(value)
                for key, value in categories_value.items()
                if normalize_category_name(key)
            }
        else:
            update_payload['categories'] = get_default_category_access()

        default_category_value = existing_data.get('default_category')
        if not isinstance(default_category_value, str) or not category_exists(update_payload['categories'].keys(), default_category_value):
            update_payload['default_category'] = next(iter(update_payload['categories'].keys()), 'Other')

        if update_payload:
            user_ref.set(update_payload, merge=True)
            existing_data.update(update_payload)
            app.logger.info(
                "Updated env admin user structure for %s source=%s",
                normalized_username,
                source,
            )

        try:
            if update_payload.get('admin_pass'):
                set_user_passes(normalized_username, admin_pass_hash=update_payload['admin_pass'])
            if update_payload.get('view_pass'):
                set_user_passes(normalized_username, view_pass_hash=update_payload['view_pass'])
        except Exception:
            app.logger.exception("Failed to set admin/view passes in user document for %s", normalized_username)

        return freeze_user_auth_entry({
            'exists': True,
            'data': existing_data,
        })

    now = datetime.now(UTC)
    user_data = {
        'username': normalized_username,
        'created_at': now,
        'bootstrap_source': source,
        'categories': get_default_category_access(),
        'default_category': 'Other',
    }
    if DEFAULT_ADMIN_PASSWORD:
        user_data['admin_pass'] = make_password_hash(DEFAULT_ADMIN_PASSWORD)
    if HW_PASSWORD:
        user_data['view_pass'] = make_password_hash(HW_PASSWORD)
    elif user_data.get('admin_pass'):
        user_data['view_pass'] = user_data['admin_pass']

    user_ref.set(user_data)
    try:
        if password:
            set_user_passes(normalized_username, admin_pass_hash=make_password_hash(password))
        if HW_PASSWORD:
            # record view_pass as well
            set_user_passes(normalized_username, view_pass_hash=make_password_hash(HW_PASSWORD))
    except Exception:
        app.logger.exception("Failed to write admin_pass to user document for %s", normalized_username)
    app.logger.info("Bootstrapped env admin user record for %s source=%s", normalized_username, source)
    return freeze_user_auth_entry({
        'exists': True,
        'data': user_data,
    })



def normalize_username(username):
    return str(username or '').strip().lower()

def freeze_user_auth_entry(entry):
    return {
        'exists': bool(entry.get('exists')),
        'data': dict(entry.get('data') or {}),
    }

def get_user_auth_entry(username):
    normalized_username = normalize_username(username)
    if not normalized_username:
        return {'exists': False, 'data': {}}
    return load_user_auth_from_store(normalized_username)

def get_user_auth_for_login(username):
    normalized_username = normalize_username(username)
    if not normalized_username:
        return {'exists': False, 'data': {}}, 'none'
    return load_user_auth_from_store(normalized_username), 'firestore'

def is_view_only_password_configured(username=None):
    if username:
        return bool(get_view_only_password_hash(username) or HW_PASSWORD)
    # Fallback: if any user has a view_pass or HW_PASSWORD exists
    if HW_PASSWORD:
        return True
    try:
        users_query = fs.collection('users').where('view_pass', '!=', '').limit(1)
        docs = list(users_query.stream(retry=None, timeout=FIRESTORE_TIMEOUT_SECONDS))
        return bool(docs)
    except Exception:
        app.logger.exception("Failed to check view-only password configuration")
    return False

def default_categories():
    return [label for _, label in CATEGORY_CHOICES]

def normalize_text(value):
    return ' '.join(str(value or '').strip().split())

def normalize_text_key(value):
    return normalize_text(value).lower()

def item_exists(items, name, normalizer=normalize_text):
    target = normalize_text_key(name)
    if not target:
        return False
    return any(normalize_text_key(normalizer(item)) == target for item in items)

def unique_normalized_items(items, normalizer=normalize_text):
    cleaned = []
    seen = set()
    for item in items:
        normalized = normalizer(item)
        key = normalized.lower()
        if normalized and key not in seen:
            cleaned.append(normalized)
            seen.add(key)
    return cleaned

def normalize_category_name(name):
    return normalize_text(name)

def category_key(name):
    return normalize_text_key(name)

def category_exists(categories, name):
    return item_exists(categories, name, normalize_category_name)

def default_split_people():
    return ['Me']

def normalize_person_name(name):
    return normalize_text(name)

def person_key(name):
    return normalize_text_key(name)

def person_exists(people, name):
    return item_exists(people, name, normalize_person_name)

def load_split_people_from_store(username=None):
    username = normalize_username(username or get_current_username() or '')
    people = []
    if username:
        doc = user_doc_ref(username).get(
            retry=None,
            timeout=FIRESTORE_TIMEOUT_SECONDS,
        )
        if doc.exists:
            raw_people = (doc.to_dict() or {}).get('split_people') or []
            people = unique_normalized_items(raw_people, normalize_person_name)
    if not people:
        people = default_split_people()
    return people

def get_split_people(username=None):
    try:
        return load_split_people_from_store(username)
    except Exception:
        app.logger.exception("Failed to load split people for %s", username)
    return default_split_people()

def save_split_people(people, updated_by=None, username=None):
    normalized_username = normalize_username(username or get_current_username() or '')
    clean_people = unique_normalized_items(people, normalize_person_name)

    if not clean_people:
        clean_people = default_split_people()

    if normalized_username:
        user_doc_ref(normalized_username).set({
            'split_people': clean_people,
            'updated_by': updated_by,
        }, merge=True)
    return clean_people

def apply_category_choices(form, include=None):
    categories = get_categories()
    include_name = normalize_category_name(include)
    if include_name and not category_exists(categories, include_name):
        categories.append(include_name)
    form.category.choices = [(item, item) for item in categories]

    default_cat = get_default_category()
    if default_cat and category_exists(categories, default_cat):
        form.category.default = default_cat
        if request.method == 'GET' and not form.category.data:
            form.category.data = default_cat

def apply_split_entry_choices(form, person_include=None, category_include=None, split_people_override=None):
    apply_category_choices(form, include=category_include)
    people = list(split_people_override) if split_people_override else get_split_people()
    include_name = normalize_person_name(person_include)
    if include_name and not person_exists(people, include_name):
        people.append(include_name)
    form.person.choices = [(item, item) for item in people]

def view_password_status_context():
    current_user = get_current_username()
    has_db_password = bool(get_user_view_pass_hash(current_user)) if current_user else False
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
    current_user = get_current_username()
    is_admin = current_user in ADMIN_USERS if current_user else False

    # Get raw categories list
    raw_categories = categories if categories is not None else get_categories()
    raw_categories = list(raw_categories)
    
    # Sorting for categories in memory
    cat_sort = request.args.get('cat_sort')
    cat_dir = request.args.get('cat_dir', 'asc')
    if cat_sort == 'category':
        raw_categories.sort(key=lambda x: x.lower(), reverse=(cat_dir == 'desc'))
    
    # Paginate categories in memory
    cat_page = parse_positive_int(request.args.get('page'), default=1)
    limit = 12
    total_cats = len(raw_categories)
    total_cat_pages = max(1, math.ceil(total_cats / limit))
    sliced_cats = raw_categories[(cat_page - 1) * limit : cat_page * limit]
    cat_pagination = SimpleNamespace(
        items=sliced_cats,
        page=cat_page,
        total_pages=total_cat_pages,
        total_items=total_cats,
        per_page=limit
    )

    # Get raw split people list
    raw_people = split_people if split_people is not None else get_split_people()
    raw_people = list(raw_people)

    # Sorting for split people in memory
    people_sort = request.args.get('people_sort')
    people_dir = request.args.get('people_dir', 'asc')
    if people_sort == 'person':
        raw_people.sort(key=lambda x: x.lower(), reverse=(people_dir == 'desc'))

    # Paginate split people in memory
    people_page = parse_positive_int(request.args.get('people_page'), default=1)
    total_people = len(raw_people)
    total_people_pages = max(1, math.ceil(total_people / limit))
    sliced_people = raw_people[(people_page - 1) * limit : people_page * limit]
    people_pagination = SimpleNamespace(
        items=sliced_people,
        page=people_page,
        total_pages=total_people_pages,
        total_items=total_people,
        per_page=limit
    )

    return render_template(
        'management.html',
        form=view_form or ViewPasswordForm(prefix='view_password'),
        reveal_form=reveal_form or ViewPasswordRevealForm(prefix='reveal_view_password'),
        revealed_current_view_password=revealed_current_view_password,
        username_form=username_form or ChangeUsernameForm(prefix='account_username'),
        password_form=password_form or ChangePasswordForm(prefix='account_password'),
        current_username=current_user or '',
        category_form=category_form or CategoryForm(prefix='category'),
        categories=cat_pagination,
        all_categories=raw_categories,
        default_category=get_default_category(),
        editing_category=editing_category,
        split_person_form=split_person_form or SplitPersonForm(prefix='split_person'),
        split_people=people_pagination,
        editing_split_person=editing_split_person,
        is_admin=is_admin,
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
    try:
        stream_iter = query.stream(
            retry=None,
            timeout=FIRESTORE_TIMEOUT_SECONDS,
        )
    except Exception as e:
        app.logger.exception("Firestore stream setup failed: %s", e)
        return iter(())

    def safe_stream():
        try:
            for doc in stream_iter:
                yield doc
        except Exception as e:
            # Don't spam full stack traces for common Firestore precondition errors
            msg = str(e)
            if 'requires an index' in msg or 'The query requires an index' in msg:
                app.logger.error("Firestore query requires a composite index: %s", msg)
            else:
                app.logger.exception("Firestore stream iteration failed: %s", e)
            return

    return safe_stream()


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

    if 'notes' in d and 'note' not in d:
        d['note'] = d['notes']
    elif 'note' in d and 'notes' not in d:
        d['notes'] = d['note']

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

def is_split_transaction(transaction):
    return bool(transaction and transaction.get('split_id'))

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
                    'recurring_id': str(rec_id),
                    'mode_name': 'recurring'
                }
                try:
                    rec_ref = rec_collection(username).document(rec_id)
                    
                    # Pre-allocate a document ID so we can use it in the balance entry
                    new_txn_ref = tx_collection(username).document()
                    new_txn_id = getattr(new_txn_ref, 'id', None)

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
                        # Use the pre-allocated reference
                        tx.set(new_txn_ref, txn_doc)
                        tx.update(rec_ref, {'last_applied': next_occ})

                    transaction.call(trans_op)
                    app.logger.info("Created transaction (txn + last_applied updated) for recurring %s at %s (user=%s) with txn_id=%s", rec_id, next_occ, username, new_txn_id)
                    # Create balance entry with type='txn' and include the transaction ID
                    try:
                        append_balance(
                            -float(txn_doc.get('amount', 0.0)),
                            'txn',
                            username=username,
                            extra_fields={'txn_id': new_txn_id, 'timestamp': next_occ},
                            mode_name='recurring',
                        )
                    except Exception:
                        app.logger.exception("Failed to append balance for recurring %s at %s (user=%s)", rec_id, next_occ, username)
                except Exception as e_tx:
                    app.logger.exception("Transaction write failed for recurring %s at %s: %s - falling back to add() (user=%s)", rec_id, next_occ, e_tx, username)
                    try:
                        # Use fallback add for transaction creation
                        res = tx_collection(username).add(txn_doc)
                        fallback_txn_id = res[1].id if isinstance(res, tuple) and len(res) > 1 else None
                        if fallback_txn_id is None and hasattr(res, 'id'):
                            fallback_txn_id = res.id
                        app.logger.info("Created transaction (fallback add) for recurring %s at %s (user=%s) with txn_id=%s", rec_id, next_occ, username, fallback_txn_id)
                        # Create balance entry with type='txn' and include the transaction ID
                        try:
                            if fallback_txn_id:
                                append_balance(
                                    -float(txn_doc.get('amount', 0.0)),
                                    'txn',
                                    username=username,
                                    extra_fields={'txn_id': fallback_txn_id, 'timestamp': next_occ},
                                    mode_name='recurring',
                                )
                            else:
                                app.logger.warning("Failed to get txn_id from fallback add for recurring %s", rec_id)
                                append_balance(
                                    -float(txn_doc.get('amount', 0.0)),
                                    'balance',
                                    username=username,
                                    notes=f"recurring:{rec_id}",
                                    extra_fields={'timestamp': next_occ},
                                    mode_name='recurring',
                                )
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
                        'balance',
                        note=balance_note,
                        username=username,
                        extra_fields={
                            'recurring_balance_id': str(rec_id),
                            'recurring_balance_key': occurrence_key,
                            'scheduled_for': next_occ,
                            'timestamp': next_occ,
                        },
                        mode_name='recurring',
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




def build_transaction_doc(form, mode_name='txn-spent'):
    txn_datetime = local_datetime_to_utc(
        form.date.data or now_ist().date(),
        form.time.data or now_ist().time(),
    )
    return {
        'amount': parse_money(form.amount.data),
        'description': validate_short_text(form.description.data, 'Description'),
        'category': form.category.data or 'Uncategorized',
        'timestamp': txn_datetime,
        'mode_name': mode_name
    }

def request_payload_signature(payload):
    try:
        normalized = json.dumps(payload or {}, sort_keys=True, separators=(',', ':'), default=str)
    except (TypeError, ValueError):
        normalized = str(payload or {})
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()


def is_recent_duplicate_request(session_key, payload, window_seconds=5):
    if payload is None:
        return False
    last = session.get(session_key)
    if not isinstance(last, dict):
        return False
    if last.get('hash') != request_payload_signature(payload):
        return False
    timestamp = last.get('ts')
    if not isinstance(timestamp, (int, float)):
        return False
    return time.time() - float(timestamp) < window_seconds


def record_request_signature(session_key, payload):
    if payload is None:
        return
    session[session_key] = {
        'hash': request_payload_signature(payload),
        'ts': time.time(),
    }


def build_transaction_doc_from_payload(payload, mode_name='txn-spent'):
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
        'mode_name': mode_name
    }

def create_transaction(username, txn_doc):
    txn_doc = dict(txn_doc)
    if 'mode_name' not in txn_doc:
        if txn_doc.get('recurring_id'):
            txn_doc['mode_name'] = 'recurring'
        elif txn_doc.get('split_id'):
            txn_doc['mode_name'] = 'split'
        else:
            txn_doc['mode_name'] = 'txn-spent'

    _, doc_ref = tx_collection(username).add(txn_doc)
    txn_id = getattr(doc_ref, 'id', '')
    
    # Determine mode_name for the balance entry
    balance_mode_name = 'txn-add'
    if txn_doc.get('mode_name') == 'recurring':
        balance_mode_name = 'recurring'
    elif txn_doc.get('mode_name') == 'split':
        balance_mode_name = 'split'
    
    balance_extra = {
        'txn_id': txn_id,
        'timestamp': txn_doc.get('timestamp') or datetime.now(UTC),
    }
    for field in ('split_id', 'split_title'):
        if txn_doc.get(field):
            balance_extra[field] = txn_doc.get(field)
    append_balance(
        -float(txn_doc['amount']),
        'txn',
        username=username,
        extra_fields=balance_extra,
        mode_name=balance_mode_name,
    )
    return txn_id


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
        username = require_user()
        if is_recent_duplicate_request('recent_add_transaction', txn_doc):
            flash('Same transaction data submitted too quickly. Please wait 5 seconds and try again.', 'warning')
            return redirect(url_for('transactions', add='true'))

        try:
            create_transaction(username, txn_doc)
            record_request_signature('recent_add_transaction', txn_doc)
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
    username = require_user()
    if is_recent_duplicate_request('api_transaction_create', payload):
        return jsonify({
            'ok': False,
            'error': 'Same transaction data submitted too quickly. Please wait 5 seconds and try again.',
        }), 429

    try:
        txn_doc = build_transaction_doc_from_payload(payload)
        txn_id = create_transaction(username, txn_doc)
        record_request_signature('api_transaction_create', payload)
        app.logger.info(
            "Transaction API create user=%s amount=%.2f",
            username,
            txn_doc['amount'],
        )
        return jsonify({
            'ok': True,
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
    username = require_user()
    if is_recent_duplicate_request(f'api_transaction_update:{tx_id}', payload):
        return jsonify({
            'ok': False,
            'error': 'Same transaction update submitted too quickly. Please wait 5 seconds and try again.',
        }), 429

    try:
        doc_ref = tx_collection(username).document(tx_id)
        doc = doc_ref.get()
        if not doc.exists:
            return jsonify({'ok': False, 'error': 'Transaction not found.'}), 404

        existing_txn = doc_to_txn(doc)
        if is_split_transaction(existing_txn):
            return jsonify({'ok': False, 'error': 'Split transactions must be updated from the Split detail page.'}), 400

        updated_doc = build_transaction_doc_from_payload(payload)
        if 'mode_name' in existing_txn:
            updated_doc['mode_name'] = existing_txn['mode_name']
        old_amount = float(existing_txn.get('amount', 0.0))
        new_amount = float(updated_doc.get('amount', 0.0))
        balance_delta = round(old_amount - new_amount, 2)
        timestamp_changed = existing_txn.get('timestamp') != updated_doc.get('timestamp')

        doc_ref.update(updated_doc)
        if balance_delta or timestamp_changed:
            update_transaction_balance_entry(
                tx_id,
                old_amount,
                new_amount,
                username=username,
                new_timestamp=updated_doc.get('timestamp'),
            )

        record_request_signature(f'api_transaction_update:{tx_id}', payload)
        app.logger.info("Transaction API update id=%s user=%s", tx_id, username)
        return jsonify({'ok': True, 'transaction_id': tx_id})
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
    username = require_user()
    if is_recent_duplicate_request(f'api_transaction_delete:{tx_id}', payload):
        return jsonify({
            'ok': False,
            'error': 'Same transaction delete submitted too quickly. Please wait 5 seconds and try again.',
        }), 429

    try:
        doc_ref = tx_collection(username).document(tx_id)
        doc = doc_ref.get()
        if not doc.exists:
            return jsonify({'ok': False, 'error': 'Transaction not found.'}), 404

        existing_txn = doc_to_txn(doc)
        if is_split_transaction(existing_txn):
            return jsonify({'ok': False, 'error': 'Split transactions must be deleted from the Split detail page.'}), 400

        delete_balance_entries_for_transaction(tx_id, username=username)
        doc_ref.delete()

        record_request_signature(f'api_transaction_delete:{tx_id}', payload)
        app.logger.info("Transaction API delete id=%s user=%s", tx_id, username)
        return jsonify({'ok': True, 'transaction_id': tx_id})
    except Exception:
        app.logger.exception("Transaction API delete failed id=%s", tx_id)
        return jsonify({'ok': False, 'error': 'Failed to delete transaction.'}), 500


@app.route('/api/transactions/<string:tx_id>/view', methods=['GET'])
@login_required
def api_get_transaction(tx_id):
    """Get transaction details for modal dialog."""
    if not session.get('logged_in'):
        abort(403, description="Full authentication required")

    username = require_user()

    try:
        doc_ref = tx_collection(username).document(tx_id)
        doc = doc_ref.get()
        if not doc.exists:
            return jsonify({'ok': False, 'error': 'Transaction not found.'}), 404

        txn = doc_to_txn(doc)
        txn_time = utc_to_ist(txn.get('timestamp')) or now_ist()

        return jsonify({
            'ok': True,
            'transaction': {
                'id': tx_id,
                'amount': round(float(txn.get('amount', 0.0)), 2),
                'description': txn.get('description', ''),
                'category': txn.get('category', 'Uncategorized'),
                'date': txn_time.date().isoformat(),
                'time': txn_time.time().isoformat()[:5],
                'timestamp': format_ist(txn.get('timestamp')) if txn.get('timestamp') else None,
                'split_id': txn.get('split_id') or '',
                'split_title': txn.get('split_title') or '',
                'split_url': url_for('split_detail', split_id=txn.get('split_id')) if txn.get('split_id') else '',
            }
        })
    except Exception:
        app.logger.exception("Failed to fetch transaction %s for user %s", tx_id, username)
        return jsonify({'ok': False, 'error': 'Failed to fetch transaction.'}), 500


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
    if is_split_transaction(existing_txn):
        flash('Split transactions must be managed from the Split detail page.', 'warning')
        return redirect(url_for('transactions'))

    form = TransactionForm()
    apply_category_choices(form, include=existing_txn.get('category'))
    form.submit.label.text = 'Update Transaction'

    if form.validate_on_submit():
        updated_doc = build_transaction_doc(form)
        if 'mode_name' in existing_txn:
            updated_doc['mode_name'] = existing_txn['mode_name']
        old_amount = float(existing_txn.get('amount', 0.0))
        new_amount = float(updated_doc.get('amount', 0.0))
        balance_delta = round(old_amount - new_amount, 2)
        timestamp_changed = existing_txn.get('timestamp') != updated_doc.get('timestamp')

        try:
            doc_ref.update(updated_doc)
            if balance_delta or timestamp_changed:
                update_transaction_balance_entry(
                    tx_id,
                    old_amount,
                    new_amount,
                    username=username,
                    new_timestamp=updated_doc.get('timestamp'),
                )
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

def transaction_search_terms(search_query):
    if not search_query:
        return []
    return [term.strip().lower() for term in search_query.split() if term.strip()]


@app.route('/api/transactions/search/count', methods=['GET'])
@login_required
def api_transactions_search_count():
    """Return an approximate count of transactions matching the search query.
    This endpoint re-uses the same memory-safe candidate-limited search as
    the main `transactions` view (candidates limited to `limit * 2`).
    """
    username = require_user()
    search = (request.args.get('query') or request.args.get('q') or '').strip()
    limit = 12

    if not search:
        return jsonify({'totalRows': 0})

    search_terms = transaction_search_terms(search)
    transactions = []
    seen_ids = set()

    def add_candidates(query):
        for doc in stream_with_timeout(query.limit(limit * 2)):
            if getattr(doc, 'id', None) in seen_ids:
                continue
            if getattr(doc, 'id', None) is not None:
                seen_ids.add(doc.id)
            transactions.append(doc_to_txn(doc))

    search_term = search.strip()
    if search_term:
        try:
            add_candidates(
                tx_collection(username)
                .where('description', '>=', search_term)
                .where('description', '<=', search_term + '\uf8ff')
            )
        except Exception:
            app.logger.debug("description search query failed")

        try:
            add_candidates(tx_collection(username).where('category', '==', search_term))
        except Exception:
            app.logger.debug("category search query failed")

        try:
            amount_value = float(search_term)
            add_candidates(tx_collection(username).where('amount', '==', amount_value))
        except (ValueError, TypeError):
            pass
        except Exception:
            app.logger.debug("amount search query failed")

    filtered_txns = []
    for txn in transactions:
        haystack = ' '.join([
            str(txn.get('id') or ''),
            str(txn.get('description') or ''),
            str(txn.get('category') or ''),
            str(txn.get('amount') or ''),
            format_ist(txn.get('timestamp')) or '',
            friendly_date_text(txn.get('timestamp')),
        ]).lower()
        if any(term in haystack for term in search_terms):
            filtered_txns.append(txn)

    return jsonify({'totalRows': len(filtered_txns)})


@app.route('/api/transactions/search', methods=['GET'])
@login_required
def api_transactions_search():
    """Return a single page of transaction search results (memory-safe).
    Query params: `query` (or `q`), `page` (default 1), `pageSize` (default 12, max 12)
    """
    username = require_user()
    search = (request.args.get('query') or request.args.get('q') or '').strip()
    page = parse_positive_int(request.args.get('page'), default=1)
    page_size = parse_positive_int(request.args.get('pageSize') or request.args.get('page_size') or request.args.get('per_page'), default=12, max_value=12)
    limit = page_size or 12

    if not search:
        return jsonify({'page': page, 'pageSize': limit, 'totalRows': 0, 'rows': []})

    # Reuse the same candidate-limited search as the transactions view
    search_terms = transaction_search_terms(search)
    transactions = []
    seen_ids = set()

    def add_candidates(query):
        for doc in stream_with_timeout(query.limit(limit * 2)):
            if getattr(doc, 'id', None) in seen_ids:
                continue
            if getattr(doc, 'id', None) is not None:
                seen_ids.add(doc.id)
            transactions.append(doc_to_txn(doc))

    search_term = search.strip()
    if search_term:
        try:
            add_candidates(
                tx_collection(username)
                .where('description', '>=', search_term)
                .where('description', '<=', search_term + '\uf8ff')
            )
        except Exception:
            app.logger.debug("description search query failed")

        try:
            add_candidates(tx_collection(username).where('category', '==', search_term))
        except Exception:
            app.logger.debug("category search query failed")

        try:
            amount_value = float(search_term)
            add_candidates(tx_collection(username).where('amount', '==', amount_value))
        except (ValueError, TypeError):
            pass
        except Exception:
            app.logger.debug("amount search query failed")

    filtered_txns = []
    for txn in transactions:
        haystack = ' '.join([
            str(txn.get('id') or ''),
            str(txn.get('description') or ''),
            str(txn.get('category') or ''),
            str(txn.get('amount') or ''),
            format_ist(txn.get('timestamp')) or '',
            friendly_date_text(txn.get('timestamp')),
        ]).lower()
        if any(term in haystack for term in search_terms):
            filtered_txns.append(txn)

    # Sort and paginate in-memory (page limited to `limit`)
    sort_arg = request.args.get('sort', 'date')
    dir_arg = request.args.get('dir', 'desc')
    sort_mapping = {
        'date': 'timestamp', 'timestamp': 'timestamp', 'description': 'description', 'category': 'category', 'amount': 'amount'
    }
    sort_field = sort_mapping.get(sort_arg, 'timestamp')
    sliced, total_items, total_pages = unified_sort_and_paginate(filtered_txns, sort_field, dir_arg, page=page, limit=limit)

    # Serialize rows for JSON
    rows = []
    for t in sliced:
        split_id = t.get('split_id') or ''
        rows.append({
            'id': t.get('_id') or t.get('id'),
            'description': t.get('description') or '',
            'category': t.get('category') or '',
            'amount': round(float(t.get('amount') or 0.0), 2),
            'timestamp': format_ist(t.get('timestamp')) if t.get('timestamp') else None,
            'split_id': split_id,
            'split_url': url_for('split_detail', split_id=split_id) if split_id else '',
        })

    return jsonify({
        'page': page,
        'pageSize': limit,
        'totalRows': total_items,
        'total_pages': total_pages,
        'rows': rows,
    })


@app.route('/api/saved_transactions/count', methods=['GET'])
@login_required
def api_saved_transactions_count():
    username = require_user()
    try:
        # Use the same fetch_sorted_page helper to get a reliable total count
        _, total_items, _ = fetch_sorted_page(
            saved_transaction_collection(username), 'created_at', firestore.Query.DESCENDING, page=1, limit=12
        )
        return jsonify({'totalRows': total_items})
    except Exception:
        app.logger.exception('Failed to fetch saved transactions count for user %s', username)
        return jsonify({'totalRows': 0}), 500


@app.route('/api/saved_transactions', methods=['GET'])
@login_required
def api_saved_transactions():
    username = require_user()
    page = parse_positive_int(request.args.get('page'), default=1)
    page_size = parse_positive_int(request.args.get('pageSize') or request.args.get('page_size') or request.args.get('per_page'), default=12, max_value=12)
    limit = page_size or 12
    try:
        items, total_items, total_pages = fetch_sorted_page(
            saved_transaction_collection(username), 'created_at', firestore.Query.DESCENDING, page=page, limit=limit
        )
        rows = []
        for s in items:
            rows.append({
                'id': s.get('_id') or s.get('id'),
                'description': s.get('description') or '',
                'category': s.get('category') or '',
                'amount': round(float(s.get('amount') or 0.0), 2),
                'timestamp': format_ist(s.get('created_at')) if s.get('created_at') else None,
            })
        return jsonify({
            'page': page,
            'pageSize': limit,
            'totalRows': total_items,
            'total_pages': total_pages,
            'rows': rows,
        })
    except Exception:
        app.logger.exception('Failed to fetch saved transactions for user %s', username)
        return jsonify({'page': page, 'pageSize': limit, 'totalRows': 0, 'total_pages': 1, 'rows': []}), 500


@app.route('/api/saved_transactions/<string:template_id>/delete', methods=['POST'])
@login_required
def api_delete_saved_transaction(template_id):
    username = require_user()
    try:
        doc_ref = saved_transaction_collection(username).document(template_id)
        doc = doc_ref.get()
        if not doc.exists:
            return jsonify({'ok': False, 'error': 'Saved transaction not found.'}), 404
        doc_ref.delete()
        app.logger.info('Saved transaction deleted id=%s user=%s', template_id, username)
        return jsonify({'ok': True, 'template_id': template_id})
    except Exception:
        app.logger.exception('Failed to delete saved transaction %s for user %s', template_id, username)
        return jsonify({'ok': False, 'error': 'Failed to delete saved transaction.'}), 500


@app.route('/api/saved_transactions/<string:template_id>/submit', methods=['POST'])
@login_required
def api_submit_saved_transaction(template_id):
    username = require_user()
    try:
        doc_ref = saved_transaction_collection(username).document(template_id)
        doc = doc_ref.get()
        if not doc.exists:
            return jsonify({'ok': False, 'error': 'Saved transaction not found.'}), 404
        txn_doc = doc_to_txn(doc)
        create_transaction(username, txn_doc)
        app.logger.info('Saved transaction submitted id=%s user=%s', template_id, username)
        return jsonify({'ok': True, 'template_id': template_id})
    except Exception:
        app.logger.exception('Failed to submit saved transaction %s for user %s', template_id, username)
        return jsonify({'ok': False, 'error': 'Failed to submit saved transaction.'}), 500

def friendly_date_text(timestamp):
    if not timestamp:
        return ""
    dt = utc_to_ist(timestamp)
    if not dt:
        return ""
    return dt.strftime("%d %B %Y %A %b").lower()

def unified_sort_and_paginate(items, sort_key, dir_arg, page=None, limit=12):
    """
    Sorts a list of dictionaries/SimpleNamespaces in-place and paginates them.
    Returns: (sliced_items, total_items, total_pages)
    """
    reverse = (dir_arg == 'desc')

    # Determine dynamic key mapping
    key_mapping = {
        'date': 'timestamp',
        'when': 'timestamp',
        'start': 'start_datetime',
        'note': 'note',
        'notes': 'note'
    }
    normalized_key = key_mapping.get(sort_key, sort_key)

    # Determine type fallback for datetime/date vs string to avoid comparisons of different types
    fallback_val = ""
    for x in items:
        v = None
        if hasattr(x, 'get'):
            if normalized_key == 'note':
                v = x.get('notes') or x.get('note')
            else:
                v = x.get(normalized_key)
        else:
            if normalized_key == 'note':
                v = getattr(x, 'notes', None) or getattr(x, 'note', None)
            else:
                v = getattr(x, normalized_key, None)
        if v is not None:
            if isinstance(v, (datetime, date)):
                fallback_val = datetime.min.replace(tzinfo=UTC)
            break

    def sort_fn(x):
        val = None
        if hasattr(x, 'get'):
            if normalized_key == 'note':
                val = x.get('notes') or x.get('note')
            else:
                val = x.get(normalized_key)
        else:
            if normalized_key == 'note':
                val = getattr(x, 'notes', None) or getattr(x, 'note', None)
            else:
                val = getattr(x, normalized_key, None)

        if normalized_key in ('amount', 'delta', 'balance'):
            try:
                return float(val or 0.0)
            except (ValueError, TypeError):
                return 0.0

        if normalized_key in ('timestamp', 'start_datetime', 'last_applied', 'created_at', 'updated_at', 'start_date'):
            if val is None:
                return fallback_val
            if isinstance(val, (int, float)):
                try:
                    return ts_to_dt(val)
                except Exception:
                    return fallback_val
            return val

        return str(val or '').lower()

    items.sort(key=sort_fn, reverse=reverse)

    total_items = len(items)
    total_pages = max(1, math.ceil(total_items / limit))

    if page is not None:
        offset = (page - 1) * limit
        sliced_items = items[offset : offset + limit]
    else:
        sliced_items = items

    return sliced_items, total_items, total_pages


def fetch_sorted_page(collection_ref, sort_key, dir_arg, page=1, limit=12, filter_query_fn=None, force_in_memory=False):
    """
    Fetches exactly `limit` items for the given page directly from the database,
    using Firestore limit/offset/order_by. If it fails due to missing indexes,
    it falls back to fetching all documents, sorting in memory, and slicing.
    Returns: (sliced_items, total_items, total_pages)
    """
    reverse = (dir_arg == 'desc')

    # 1. Resolve key mapping
    key_mapping = {
        'date': 'timestamp',
        'when': 'timestamp',
        'start': 'start_datetime',
        'note': 'note',
        'notes': 'note'
    }
    normalized_key = key_mapping.get(sort_key, sort_key)
    direction = firestore.Query.DESCENDING if reverse else firestore.Query.ASCENDING

    # 2. Get base query
    base_q = collection_ref
    if filter_query_fn:
        base_q = filter_query_fn(base_q)

    # Normalize page/limit to safe integers
    try:
        page = int(page) if page is not None else 1
    except (TypeError, ValueError):
        page = 1
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 12
    limit = max(1, min(limit, 12))

    # If caller requests in-memory sorting, do a full fetch and sort locally.
    if force_in_memory:
        try:
            docs = list(stream_with_timeout(base_q))
            items = [doc_to_txn(doc) for doc in docs]
            total_items = len(items)
            items, _, _ = unified_sort_and_paginate(items, normalized_key, dir_arg, page=None, limit=total_items)
            offset = (page - 1) * limit
            sliced = items[offset: offset + limit]
            total_pages = max(1, math.ceil(total_items / limit))
            return sliced, total_items, total_pages
        except Exception:
            app.logger.warning("Forced in-memory fetch_sorted_page failed, falling back to DB query")

    # 3. Try database-level sorting and pagination
    try:
        # First check the count using Firestore count query (very cheap & fast)
        try:
            total_items = base_q.count().get()[0][0].value
        except Exception:
            total_items = 0

        total_pages = max(1, math.ceil(total_items / limit))
        offset = (page - 1) * limit

        q = base_q.order_by(normalized_key, direction=direction).offset(offset).limit(limit)
        docs = list(stream_with_timeout(q))
        items = [doc_to_txn(doc) for doc in docs]

        # If count indicates there are items but ordered fetch returned none
        # (often due to missing composite index causing stream to abort early),
        # attempt a best-effort unordered full fallback to return correct rows.
        if not items and total_items > 0:
            try:
                app.logger.warning("Ordered fetch returned no docs but count>0; attempting unordered full fallback")
                # Fetch all matching documents and sort them in memory by the requested field.
                docs2 = list(stream_with_timeout(base_q))
                items2 = [doc_to_txn(doc) for doc in docs2]
                if items2:
                    items2, _, _ = unified_sort_and_paginate(items2, normalized_key, dir_arg, page=None, limit=len(items2))
                    offset = (page - 1) * limit
                    sliced = items2[offset: offset + limit]
                    total_pages = max(1, math.ceil(total_items / limit))
                    return sliced, total_items, total_pages
            except Exception:
                app.logger.warning("Unordered full fallback also failed")
        return items, total_items, total_pages

    except Exception as e:
        msg = str(e)
        if 'requires an index' in msg or 'The query requires an index' in msg:
            app.logger.warning("Firestore composite index required; falling back to in-memory sort. Error: %s", msg)
            try:
                app.logger.warning("Attempting in-memory fallback after missing index error")
                docs = list(stream_with_timeout(base_q))
                items = [doc_to_txn(doc) for doc in docs]
                total_items = len(items)
                items, _, _ = unified_sort_and_paginate(items, normalized_key, dir_arg, page=None, limit=total_items)
                offset = (page - 1) * limit
                sliced = items[offset: offset + limit]
                total_pages = max(1, math.ceil(total_items / limit))
                return sliced, total_items, total_pages
            except Exception as e2:
                app.logger.warning("In-memory fallback after missing index error failed: %s", str(e2))
                return [], 0, 1
        app.logger.warning("Firestore query failed, falling back to limited memory page: %s", msg)

        try:
            offset = (page - 1) * limit
            q = base_q.order_by(normalized_key, direction=direction).offset(offset).limit(limit)
            docs = list(stream_with_timeout(q))
            items = [doc_to_txn(doc) for doc in docs]
            total_items = len(items)
            total_pages = max(1, math.ceil(total_items / limit))
            return items, total_items, total_pages
        except Exception as fallback_error:
            app.logger.warning("Limited fallback query also failed: %s", str(fallback_error))
            return [], 0, 1




@app.route('/transactions')
@login_required
def transactions():
    search = (request.args.get('q') or '').strip()
    username = require_user()

    page = parse_positive_int(request.args.get('page'), default=1)
    limit = 12

    # Sorting
    sort_arg = request.args.get('sort', 'date')
    dir_arg = request.args.get('dir', 'desc')

    sort_mapping = {
        'date': 'timestamp',
        'timestamp': 'timestamp',
        'description': 'description',
        'category': 'category',
        'amount': 'amount'
    }
    sort_field = sort_mapping.get(sort_arg, 'timestamp')
    direction = firestore.Query.DESCENDING if dir_arg == 'desc' else firestore.Query.ASCENDING

    if search:
        search_terms = transaction_search_terms(search)
        transactions = []
        seen_ids = set()

        def add_candidates(query):
            for doc in stream_with_timeout(query.limit(limit * 2)):
                if getattr(doc, 'id', None) in seen_ids:
                    continue
                if getattr(doc, 'id', None) is not None:
                    seen_ids.add(doc.id)
                transactions.append(doc_to_txn(doc))

        search_term = search.strip()
        if search_term:
            try:
                add_candidates(
                    tx_collection(username)
                    .where('description', '>=', search_term)
                    .where('description', '<=', search_term + '\uf8ff')
                )
            except Exception as e:
                app.logger.warning("Transaction description search query failed: %s", str(e))

            try:
                add_candidates(tx_collection(username).where('category', '==', search_term))
            except Exception as e:
                app.logger.warning("Transaction category search query failed: %s", str(e))

            try:
                amount_value = float(search_term)
                add_candidates(tx_collection(username).where('amount', '==', amount_value))
            except (ValueError, TypeError):
                pass
            except Exception as e:
                app.logger.warning("Transaction amount search query failed: %s", str(e))

        filtered_txns = []
        for txn in transactions:
            haystack = ' '.join([
                str(txn.get('id') or ''),
                str(txn.get('description') or ''),
                str(txn.get('category') or ''),
                str(txn.get('amount') or ''),
                format_ist(txn.get('timestamp')) or '',
                friendly_date_text(txn.get('timestamp')),
            ]).lower()
            if any(term in haystack for term in search_terms):
                filtered_txns.append(txn)

        txns_list, total_items, total_pages = unified_sort_and_paginate(
            filtered_txns, sort_field, dir_arg, page=page, limit=limit
        )
    else:
        txns_list, total_items, total_pages = fetch_sorted_page(
            tx_collection(username), sort_field, dir_arg, page=page, limit=limit
        )


    saved_page = parse_positive_int(request.args.get('saved_page'), default=1)
    saved_txns_list, saved_total_items, saved_total_pages = fetch_sorted_page(
        saved_transaction_collection(username), 'created_at', firestore.Query.DESCENDING, page=saved_page, limit=limit
    )
    saved_paginate_obj = SimpleNamespace(
        items=saved_txns_list,
        page=saved_page,
        total_pages=saved_total_pages,
        total_items=saved_total_items,
        per_page=limit,
    )

    paginate_obj = SimpleNamespace(
        items=txns_list,
        search=search,
        page=page,
        total_pages=total_pages,
        total_items=total_items,
        per_page=limit,
        latest_transaction_id=get_latest_transaction_id(username=username),
    )

    form = TransactionForm()
    apply_category_choices(form)

    return render_template(
        'transactions.html',
        txns=paginate_obj,
        saved_txns=saved_paginate_obj,
        form=form,
    )

@app.route('/delete/<string:tx_id>', methods=['POST'])
@login_required
def delete(tx_id):
    username = require_user()
    doc_ref = tx_collection(username).document(tx_id)
    doc = doc_ref.get()
    if not doc.exists:
        flash('Transaction not found.', 'warning')
        return redirect(url_for('transactions'))

    txn = doc_to_txn(doc)
    if is_split_transaction(txn):
        flash('Split transactions must be deleted from the Split detail page.', 'warning')
        return redirect(url_for('transactions'))

    try:
        delete_balance_entries_for_transaction(tx_id, username=username)
        doc_ref.delete()
        flash('Transaction deleted.', 'danger')
    except Exception as e:
        app.logger.exception("Failed to delete transaction %s: %s", tx_id, e)
        flash('Failed to delete transaction.', 'warning')

    return redirect(url_for('transactions'))

@app.route('/saved_transactions/add', methods=['POST'])
@login_required
def add_saved_transaction():
    username = require_user()
    form = TransactionForm()
    apply_category_choices(form)
    if form.validate_on_submit():
        txn_doc = build_transaction_doc(form)
        txn_doc['created_at'] = datetime.now(UTC)
        txn_doc['updated_at'] = txn_doc['created_at']
        try:
            saved_transaction_collection(username).add(txn_doc)
            flash('Saved transaction template added.', 'success')
        except Exception as e:
            app.logger.exception('Failed to add saved transaction template: %s', e)
            flash('Failed to add saved transaction template.', 'warning')
    else:
        flash('Please correct the saved transaction form errors.', 'warning')
    return redirect(url_for('transactions'))

@app.route('/saved_transactions/<string:template_id>/edit', methods=['POST'])
@login_required
def edit_saved_transaction(template_id):
    username = require_user()
    doc_ref = saved_transaction_collection(username).document(template_id)
    doc = doc_ref.get()
    if not doc.exists:
        flash('Saved transaction not found.', 'warning')
        return redirect(url_for('transactions'))

    form = TransactionForm()
    apply_category_choices(form)
    if form.validate_on_submit():
        updated_doc = build_transaction_doc(form)
        updated_doc['updated_at'] = datetime.now(UTC)
        try:
            doc_ref.update(updated_doc)
            flash('Saved transaction template updated.', 'success')
        except Exception as e:
            app.logger.exception('Failed to update saved transaction template %s: %s', template_id, e)
            flash('Failed to update saved transaction template.', 'warning')
    else:
        flash('Please correct the edit form errors.', 'warning')
    return redirect(url_for('transactions'))

@app.route('/saved_transactions/<string:template_id>/delete', methods=['POST'])
@login_required
def delete_saved_transaction(template_id):
    username = require_user()
    doc_ref = saved_transaction_collection(username).document(template_id)
    doc = doc_ref.get()
    if not doc.exists:
        flash('Saved transaction not found.', 'warning')
        return redirect(url_for('transactions'))
    try:
        doc_ref.delete()
        flash('Saved transaction template deleted.', 'info')
    except Exception as e:
        app.logger.exception('Failed to delete saved transaction template %s: %s', template_id, e)
        flash('Failed to delete saved transaction template.', 'warning')
    return redirect(url_for('transactions'))

@app.route('/saved_transactions/<string:template_id>/submit', methods=['POST'])
@login_required
def submit_saved_transaction(template_id):
    username = require_user()
    doc_ref = saved_transaction_collection(username).document(template_id)
    doc = doc_ref.get()
    if not doc.exists:
        flash('Saved transaction not found.', 'warning')
        return redirect(url_for('transactions'))

    txn_doc = doc_to_txn(doc)
    try:
        create_transaction(username, txn_doc)
        flash('Saved transaction submitted to transactions.', 'success')
    except Exception as e:
        app.logger.exception('Failed to submit saved transaction %s: %s', template_id, e)
        flash('Failed to submit saved transaction.', 'warning')
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

def get_recurring_rules_for_page(username, page=None, limit=12, sort_field='start_datetime', direction=firestore.Query.DESCENDING):
    dir_arg = 'desc' if direction == firestore.Query.DESCENDING else 'asc'
    sliced, _, _ = fetch_sorted_page(rec_collection(username), sort_field, dir_arg, page=page, limit=limit)
    return sliced

def get_recurring_rules_count(username):
    try:
        return rec_collection(username).count().get()[0][0].value
    except Exception:
        return 0

def get_recurring_balance_rules_for_page(username, page=None, limit=12, sort_field='start_datetime', direction=firestore.Query.DESCENDING):
    dir_arg = 'desc' if direction == firestore.Query.DESCENDING else 'asc'
    sliced, _, _ = fetch_sorted_page(rec_balance_collection(username), sort_field, dir_arg, page=page, limit=limit)
    return sliced


def get_recurring_balance_rules_count(username):
    try:
        return rec_balance_collection(username).count().get()[0][0].value
    except Exception:
        return 0


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
    balance_form = RecurringBalanceForm(prefix='balance')
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

    # Sorting for recurring expenses
    sort_arg = request.args.get('sort', 'start')
    dir_arg = request.args.get('dir', 'desc')

    sort_mapping = {
        'start': 'start_datetime',
        'amount': 'amount',
        'description': 'description',
        'frequency': 'frequency',
        'last_applied': 'last_applied'
    }
    sort_field = sort_mapping.get(sort_arg, 'start_datetime')
    direction = firestore.Query.DESCENDING if dir_arg == 'desc' else firestore.Query.ASCENDING

    # Pagination for recurring expenses
    page = parse_positive_int(request.args.get('page'), default=1)
    limit = 12
    total_recs = get_recurring_rules_count(username)
    total_recs_pages = max(1, math.ceil(total_recs / limit))
    recs_list = get_recurring_rules_for_page(username, page=page, limit=limit, sort_field=sort_field, direction=direction)
    recs_pagination = SimpleNamespace(
        items=recs_list,
        page=page,
        total_pages=total_recs_pages,
        total_items=total_recs,
        per_page=limit
    )

    # Sorting for recurring balance rules
    balance_sort_arg = request.args.get('balance_sort', 'start')
    balance_dir_arg = request.args.get('balance_dir', 'desc')

    balance_sort_field = sort_mapping.get(balance_sort_arg, 'start_datetime')
    balance_direction = firestore.Query.DESCENDING if balance_dir_arg == 'desc' else firestore.Query.ASCENDING

    # Pagination for recurring balance rules
    balance_page = parse_positive_int(request.args.get('balance_page'), default=1)
    total_balance_recs = get_recurring_balance_rules_count(username)
    total_balance_pages = max(1, math.ceil(total_balance_recs / limit))
    balance_list = get_recurring_balance_rules_for_page(username, page=balance_page, limit=limit, sort_field=balance_sort_field, direction=balance_direction)
    balance_pagination = SimpleNamespace(
        items=balance_list,
        page=balance_page,
        total_pages=total_balance_pages,
        total_items=total_balance_recs,
        per_page=limit
    )

    return render_template(
        'recurring.html',
        form=form,
        balance_form=balance_form,
        recs=recs_pagination,
        balance_recs=balance_pagination,
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
    form = RecurringBalanceForm(prefix='balance')
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


def get_trip_documents(username=None, page=None, limit=12):
    if username is None:
        username = require_user()
    sliced, _, _ = fetch_sorted_page(trips_collection(username), 'start_date', 'desc', page=page, limit=limit)

    trips = []
    for t in sliced:
        if t.get('cost_type') == 'split' and t.get('split_id'):
            try:
                split_doc = splits_collection(username).document(t['split_id']).get()
                split_people = []
                if split_doc.exists:
                    split_people = split_doc.to_dict().get('people', [])
                totals = get_split_totals(t['split_id'], username=username)
                num_people = len(split_people) or len(totals)
                t['approx_cost'] = round(sum(totals.values()) / num_people, 2) if num_people > 0 else 0.0
            except Exception as e:
                app.logger.error("Error calculating dynamic split cost for trip %s: %s", t.get('_id'), str(e))
                t['approx_cost'] = float(t.get('approx_cost') or 0.0)
        else:
            t['approx_cost'] = float(t.get('approx_cost') or 0.0)
        trips.append(t)
    return trips


def get_trips_count(username=None):
    if username is None:
        username = require_user()
    try:
        return trips_collection(username).count().get()[0][0].value
    except Exception:
        return 0

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

def get_splits_count(username=None):
    if username is None:
        username = require_user()
    try:
        return splits_collection(username).count().get()[0][0].value
    except Exception:
        return 0

def get_split_documents(username=None, page=None, limit=12, sort_field='updated_at', direction=firestore.Query.DESCENDING):
    if username is None:
        username = require_user()
    dir_arg = 'desc' if direction == firestore.Query.DESCENDING else 'asc'
    sliced, _, _ = fetch_sorted_page(splits_collection(username), sort_field, dir_arg, page=page, limit=limit)
    return sliced

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

def get_split_entries_count(split_id, username=None):
    if username is None:
        username = require_user()
    try:
        return split_entries_collection(split_id, username).count().get()[0][0].value
    except Exception:
        return 0

def get_split_entries(split_id, username=None, page=None, limit=12, sort_field='timestamp', direction=firestore.Query.DESCENDING):
    if username is None:
        username = require_user()
    dir_arg = 'desc' if direction == firestore.Query.DESCENDING else 'asc'
    sliced, _, _ = fetch_sorted_page(split_entries_collection(split_id, username), sort_field, dir_arg, page=page, limit=limit)
    return sliced

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
    entries = get_split_entries(split_id, username=username)
    return {
        'id': split_id,
        'title': split_doc.get('title') or 'Untitled split',
        'is_live': bool(split_doc.get('is_live')),
        'updated_at': format_ist(split_doc.get('updated_at')) if split_doc.get('updated_at') else None,
        'totals': [{'person': person, 'amount': amount} for person, amount in sorted(totals.items())],
        'entries': [serialize_split_entry(entry) for entry in entries],
    }

def create_split_entry(username, split_id, entry_doc):
    split_ref = splits_collection(username).document(split_id)
    if not split_ref.get().exists:
        raise LookupError('Split not found.')

    entry_doc = dict(entry_doc)
    entry_doc['created_at'] = entry_doc.get('created_at') or datetime.now(UTC)
    entry_ref = split_entries_collection(split_id, username).document()
    entry_ref.set(entry_doc, merge=True)
    split_ref.set({'updated_at': datetime.now(UTC)}, merge=True)

    return entry_ref.id


@app.route('/splits', methods=['GET', 'POST'])
@login_required
def splits():
    username = require_user()
    if session.get('view_only') and request.method != 'GET':
        abort(401, description="View-only sessions cannot create splits")

    form = SplitDocumentForm()
    if session.get('view_only'):
        form = SplitDocumentForm(formdata=None)

    if not session.get('view_only') and request.method == 'POST':
        # JSON API payload check
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            title = validate_short_text(payload.get('title'), 'Title')
            is_live = bool(payload.get('is_live'))
            people = payload.get('people', [])
            split_doc = {
                'title': title,
                'is_live': is_live,
                'people': people,
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
            split_doc['people'] = request.form.getlist('people')
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

    page = parse_positive_int(request.args.get('page'), default=1)
    limit = 12

    # Sorting
    sort_arg = request.args.get('sort', 'updated')
    dir_arg = request.args.get('dir', 'desc')

    sort_mapping = {
        'name': 'title',
        'title': 'title',
        'updated': 'updated_at',
        'updated_at': 'updated_at'
    }
    sort_field = sort_mapping.get(sort_arg, 'updated_at')
    direction = firestore.Query.DESCENDING if dir_arg == 'desc' else firestore.Query.ASCENDING

    total_items = get_splits_count(username=username)
    total_pages = max(1, math.ceil(total_items / limit))

    splits_list = get_split_documents(
        username=username,
        page=page,
        limit=limit,
        sort_field=sort_field,
        direction=direction
    )
    for s in splits_list:
        sid = s.get('_id') or s.get('id')
        totals = get_split_totals(sid, username=username)
        total_spent = sum(totals.values())
        num_people = len(s.get('people', [])) or len(totals)
        s['share_amount'] = round(total_spent / num_people, 2) if num_people > 0 else 0.0

    paginate_obj = SimpleNamespace(
        items=splits_list,
        page=page,
        total_pages=total_pages,
        total_items=total_items,
        per_page=limit
    )

    return render_template(
        'splits.html',
        form=form,
        splits=paginate_obj,
        live_split=get_live_split(username=username),
        trip_map=get_trip_split_map(username=username),
        all_people=get_split_people(),
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

    page = parse_positive_int(request.args.get('page'), default=1)
    limit = 12

    # Sorting
    sort_arg = request.args.get('sort', 'when')
    dir_arg = request.args.get('dir', 'desc')

    sort_mapping = {
        'when': 'timestamp',
        'timestamp': 'timestamp',
        'person': 'person',
        'for': 'description',
        'description': 'description',
        'category': 'category',
        'amount': 'amount'
    }
    sort_field = sort_mapping.get(sort_arg, 'timestamp')
    direction = firestore.Query.DESCENDING if dir_arg == 'desc' else firestore.Query.ASCENDING

    total_items = get_split_entries_count(split_id, username=username)
    total_pages = max(1, math.ceil(total_items / limit))

    entries_list = get_split_entries(
        split_id,
        username=username,
        page=page,
        limit=limit,
        sort_field=sort_field,
        direction=direction
    )

    entries_pagination = SimpleNamespace(
        items=entries_list,
        page=page,
        total_pages=total_pages,
        total_items=total_items,
        per_page=limit
    )

    totals = get_split_totals(split_id, username=username)
    total_spent = sum(totals.values())
    num_people = len(split_data.get('people', [])) or len(totals)
    share_amount = round(total_spent / num_people, 2) if num_people > 0 else 0.0

    entry_form = SplitEntryForm()
    apply_split_entry_choices(entry_form, split_people_override=split_data.get('people'))
    return render_template(
        'split_detail.html',
        split_doc=split_data,
        entry_form=entry_form,
        entries=entries_pagination,
        totals=totals,
        total_spent=total_spent,
        num_people=num_people,
        share_amount=share_amount,
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
            'people': payload.get('people', []),
            'updated_at': datetime.now(UTC),
        }
        doc_ref.set(update_doc, merge=True)
        app.logger.info("Split updated via JSON id=%s user=%s", split_id, username)
        return jsonify({'ok': True})

    if form.validate_on_submit():
        update_doc = build_split_document_doc(form)
        update_doc['people'] = request.form.getlist('people')
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
    split_ref = splits_collection(username).document(split_id)
    split_doc = split_ref.get()
    if not split_doc.exists:
        app.logger.warning("Split entry add requested for missing split id=%s user=%s", split_id, username)
        flash('Split not found.', 'warning')
        return redirect(url_for('splits'))

    split_data = doc_to_txn(split_doc)
    form = SplitEntryForm()
    apply_split_entry_choices(form, split_people_override=split_data.get('people'))
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
    apply_split_entry_choices(form, person_include=entry.get('person'), category_include=entry.get('category'), split_people_override=split_doc.to_dict().get('people'))
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
    if is_recent_duplicate_request(f'api_split_entry_create:{split_id}', payload):
        return jsonify({
            'ok': False,
            'error': 'Same split entry data submitted too quickly. Please wait 5 seconds and try again.',
        }), 429

    username = require_user()
    try:
        entry_doc = build_split_entry_doc_from_payload(payload)
        entry_id = create_split_entry(username, split_id, entry_doc)
        record_request_signature(f'api_split_entry_create:{split_id}', payload)
        app.logger.info(
            "Split entry API create split=%s entry=%s user=%s",
            split_id,
            entry_id,
            username,
        )
        split_doc = doc_to_txn(splits_collection(username).document(split_id).get())
        return jsonify({
            'ok': True,
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
    if is_recent_duplicate_request(f'api_split_entry_update:{split_id}:{entry_id}', payload):
        return jsonify({
            'ok': False,
            'error': 'Same split entry update submitted too quickly. Please wait 5 seconds and try again.',
        }), 429

    username = require_user()
    try:
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

        record_request_signature(f'api_split_entry_update:{split_id}:{entry_id}', payload)
        app.logger.info("Split entry API update split=%s entry=%s user=%s", split_id, entry_id, username)
        return jsonify({
            'ok': True,
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
    if is_recent_duplicate_request(f'api_split_entry_delete:{split_id}:{entry_id}', payload):
        return jsonify({
            'ok': False,
            'error': 'Same split entry delete submitted too quickly. Please wait 5 seconds and try again.',
        }), 429

    username = require_user()
    try:
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

        record_request_signature(f'api_split_entry_delete:{split_id}:{entry_id}', payload)
        app.logger.info("Split entry API delete split=%s entry=%s user=%s", split_id, entry_id, username)
        return jsonify({
            'ok': True,
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


@app.route('/splits/<string:split_id>/record_txn', methods=['POST'])
@login_required
def split_record_txn(split_id):
    if session.get('view_only'):
        abort(401, description="View-only sessions cannot record transactions")

    username = require_user()
    split_ref = splits_collection(username).document(split_id)
    split_doc = split_ref.get()
    if not split_doc.exists:
        flash('Split not found.', 'warning')
        return redirect(url_for('splits'))

    split_data = doc_to_txn(split_doc)
    totals = get_split_totals(split_id, username=username)
    total_spent = sum(totals.values())
    num_people = len(split_data.get('people', [])) or len(totals)

    if num_people <= 0:
        flash('No participants found to calculate share.', 'warning')
        return redirect(url_for('splits'))

    share_amount = round(total_spent / num_people, 2)
    txn_amount = share_amount

    overwrite = request.form.get('overwrite') == 'true'
    existing_txn_id = split_data.get('transaction_id')

    txns_col = tx_collection(username)
    txn_id = existing_txn_id

    if txn_id and overwrite:
        txn_ref = txns_col.document(txn_id)
        if txn_ref.get().exists:
            existing_txn = doc_to_txn(txn_ref.get())
            old_amount = float(existing_txn.get('amount', 0.0))
            new_amount = float(txn_amount)
            balance_delta = round(old_amount - new_amount, 2)

            if balance_delta:
                update_transaction_balance_entry(
                    txn_id,
                    old_amount,
                    new_amount,
                    username=username,
                    new_timestamp=existing_txn.get('timestamp'),
                )

            txn_ref.update({
                'amount': float(txn_amount),
                'description': f"Split share: {split_data.get('title')}",
                'category': 'Split',
                'split_id': split_id,
                'split_title': split_data.get('title') or 'Untitled split',
                'updated_at': datetime.now(UTC)
            })
            for balance_doc in find_balance_entries_for_transaction(txn_id, username=username):
                bal_collection(username).document(balance_doc.id).update({
                    'split_id': split_id,
                    'split_title': split_data.get('title') or 'Untitled split',
                    'updated_at': datetime.now(UTC),
                })
            split_ref.update({
                'recorded_amount': float(share_amount),
                'updated_at': datetime.now(UTC)
            })
            flash(f"Successfully re-synced split share of Rs. {share_amount} in transactions!", 'success')
            return redirect(url_for('splits'))
        else:
            txn_id = None

    if not txn_id or not overwrite:
        # Create a new transaction
        txn_doc = {
            'amount': float(txn_amount),
            'description': f"Split share: {split_data.get('title')}",
            'category': 'Split',
            'split_id': split_id,
            'split_title': split_data.get('title') or 'Untitled split',
            'timestamp': datetime.now(UTC),
            'created_at': datetime.now(UTC),
            'updated_at': datetime.now(UTC)
        }

        # We call create_transaction helper to add and adjust balance
        txn_id = create_transaction(username, txn_doc)
        split_ref.update({
            'transaction_id': txn_id,
            'recorded_amount': float(share_amount),
            'updated_at': datetime.now(UTC)
        })
        flash(f"Successfully recorded split share of Rs. {share_amount} as a Trip Expense!", 'success')

    return redirect(url_for('splits'))


# ---------------------------------------------------------------------
# Trips Routes (Create, Edit, Delete, Disconnect)
# ---------------------------------------------------------------------

@app.route('/trips', methods=['GET', 'POST'])
@login_required
def trips():
    username = require_user()
    if session.get('view_only') and request.method != 'GET':
        abort(401, description="View-only sessions cannot create trips")

    form = TripForm()
    if session.get('view_only'):
        form = TripForm(formdata=None)

    if not session.get('view_only') and request.method == 'POST':
        # JSON API payload check for direct online submissions.
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            name = validate_short_text(payload.get('name'), 'Trip Name')
            start_date_str = payload.get('start_date')
            end_date_str = payload.get('end_date')
            description_raw = (payload.get('description') or '').strip()
            photo_link_raw = (payload.get('photo_link') or '').strip()
            description = validate_short_text(description_raw, 'Description', max_length=500) if description_raw else ''
            photo_link = validate_short_text(photo_link_raw, 'Photos Link', max_length=255) if photo_link_raw else ''
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
                    'people': payload.get('people', []),
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
                    'people': request.form.getlist('people'),
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
    page = parse_positive_int(request.args.get('page'), default=1)
    limit = 12
    total_items = get_trips_count(username=username)
    total_pages = max(1, math.ceil(total_items / limit))
    trips_list = get_trip_documents(username=username, page=page, limit=limit)

    paginate_obj = SimpleNamespace(
        items=trips_list,
        page=page,
        total_pages=total_pages,
        total_items=total_items,
        per_page=limit
    )

    splits_list = get_split_documents(username=username)
    return render_template(
        'trips.html',
        form=form,
        trips=paginate_obj,
        splits=splits_list,
        all_people=get_split_people(),
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
        description_raw = (payload.get('description') or '').strip()
        photo_link_raw = (payload.get('photo_link') or '').strip()
        description = validate_short_text(description_raw, 'Description', max_length=500) if description_raw else ''
        photo_link = validate_short_text(photo_link_raw, 'Photos Link', max_length=255) if photo_link_raw else ''
        cost_type = payload.get('cost_type', 'fixed')
        approx_cost_val = float(payload.get('approx_cost') or 0.0)

        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        except Exception:
            return jsonify({'ok': False, 'error': 'Invalid date format (use YYYY-MM-DD)'}), 400

        split_id = existing.get('split_id')
        if cost_type == 'split':
            if not split_id:
                split_doc = {
                    'title': name,
                    'is_live': False,
                    'people': payload.get('people', []),
                    'created_at': datetime.now(UTC),
                    'updated_at': datetime.now(UTC),
                }
                split_ref = splits_collection(username).document()
                split_ref.set(split_doc)
                split_id = split_ref.id
                approx_cost_val = 0.0
            else:
                splits_collection(username).document(split_id).set({
                    'title': name,
                    'people': payload.get('people', []),
                    'updated_at': datetime.now(UTC)
                }, merge=True)
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
        if cost_type == 'split':
            if not split_id:
                split_doc = {
                    'title': name,
                    'is_live': False,
                    'people': request.form.getlist('people'),
                    'created_at': datetime.now(UTC),
                    'updated_at': datetime.now(UTC),
                }
                split_ref = splits_collection(username).document()
                split_ref.set(split_doc)
                split_id = split_ref.id
                approx_cost_val = 0.0
            else:
                splits_collection(username).document(split_id).set({
                    'title': name,
                    'people': request.form.getlist('people'),
                    'updated_at': datetime.now(UTC)
                }, merge=True)
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

def verify_view_only_password(username, provided_pw):
    """
    Verify the view-only password for a specific user.
    Per-user view password stored in the user document is checked first.
    Falls back to `VIEW_PASS` env var if configured.
    """
    if not provided_pw:
        return False

    stored_hash = get_view_only_password_hash(username)
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
    if not verify_password(get_user_auth_password_hash(user_data), password):
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
    new_ref.set(new_data, merge=True)

    copied_docs = []
    for collection_name in ('transactions', 'recurring', 'recurring_balances', 'balances'):
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
        if username not in ADMIN_USERS:
            flash('Only administrators can change the view-only password.', 'danger')
            return redirect(url_for('management'))
        password_hash = make_password_hash(form.password.data.strip())
        # store per-user view password in the user document
        set_user_passes(username, view_pass_hash=password_hash)
        app.logger.info("View-only password updated by user=%s", username)
        flash('View-only password updated successfully.', 'success')
        return redirect(url_for('management'))

    if action == 'reveal_view_password' and reveal_form.validate_on_submit():
        if username not in ADMIN_USERS:
            flash('Only administrators can access the view-only password.', 'danger')
            return redirect(url_for('management'))
        entered_password = reveal_form.current_password.data.strip()
        if verify_view_only_password(username, entered_password):
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
            user_doc_ref(username).set({
                'admin_pass': password_hash,
                'view_pass': password_hash,
            }, merge=True)
            user_data = dict(user_data or {})
            user_data.update({
                'admin_pass': password_hash,
                'view_pass': password_hash,
            })
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
    categories = get_categories(username)
    category_form = CategoryForm(prefix='category')
    category_form.submit.label.text = 'Update Category'

    if not category_exists(categories, original):
        flash('Category not found.', 'warning')
        return redirect(url_for('management'))

    if category_is_protected(original, username):
        if request.is_json:
            return jsonify({'ok': False, 'error': 'This system category is protected and cannot be edited or deleted.'}), 400
        flash('This system category is protected and cannot be edited or deleted.', 'warning')
        return redirect(url_for('management'))

    if request.is_json:
        payload = request.get_json(silent=True) or {}
        updated = normalize_category_name(payload.get('name'))
        if not updated:
            return jsonify({'ok': False, 'error': 'Name is required'}), 400
        if category_key(updated) != category_key(original) and category_exists(categories, updated):
            return jsonify({'ok': False, 'error': 'Category already exists.'}), 400
        renamed = [updated if category_key(item) == category_key(original) else item for item in categories]
        default_cat = get_default_category(username)
        if category_key(default_cat) == category_key(original):
            default_cat = updated
        save_categories(renamed, updated_by=username)
        user_doc_ref(username).set({
            'default_category': default_cat,
        }, merge=True)
        app.logger.info("Category renamed via JSON old=%s new=%s user=%s", original, updated, username)
        return jsonify({'ok': True})

    if category_form.validate_on_submit():
        updated = normalize_category_name(category_form.name.data)
        if category_key(updated) != category_key(original) and category_exists(categories, updated):
            flash('Category already exists.', 'warning')
            return redirect(url_for('management', edit='true', edit_id=original))

        renamed = [updated if category_key(item) == category_key(original) else item for item in categories]
        default_cat = get_default_category(username)
        if category_key(default_cat) == category_key(original):
            default_cat = updated
        save_categories(renamed, updated_by=username)
        user_doc_ref(username).set({
            'default_category': default_cat,
        }, merge=True)
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
    if category_is_protected(category, username):
        if request.is_json:
            return jsonify({'ok': False, 'error': 'This system category is protected and cannot be edited or deleted.'}), 400
        flash('This system category is protected and cannot be edited or deleted.', 'warning')
        return redirect(url_for('management'))

    categories = get_categories(username)
    remaining = [item for item in categories if category_key(item) != category_key(category)]

    if len(remaining) == len(categories):
        flash('Category not found.', 'warning')
        return redirect(url_for('management'))

    if not remaining:
        flash('At least one category is required.', 'warning')
        return redirect(url_for('management'))

    if request.is_json:
        default_cat = get_default_category(username)
        if category_key(default_cat) == category_key(category):
            default_cat = remaining[0] if remaining else 'Other'
        save_categories(remaining, updated_by=username)
        user_doc_ref(username).set({
            'default_category': default_cat,
        }, merge=True)
        app.logger.info("Category deleted via JSON name=%s user=%s", category, username)
        return jsonify({'ok': True})

    default_cat = get_default_category(username)
    if category_key(default_cat) == category_key(category):
        default_cat = remaining[0] if remaining else 'Other'
    save_categories(remaining, updated_by=username)
    user_doc_ref(username).set({
        'default_category': default_cat,
    }, merge=True)
    app.logger.info("Category deleted name=%s user=%s", category, username)
    flash('Category deleted.', 'info')
    return redirect(url_for('management'))


@app.route('/management/set_default_category', methods=['POST'])
@login_required
def management_set_default_category():
    username = require_user()
    if session.get('view_only'):
        flash("Action not allowed in view-only mode", "error")
        return redirect(url_for('management'))

    default_cat = request.form.get('default_category')
    categories = get_categories(username)
    if default_cat and category_exists(categories, default_cat):
        try:
            user_doc_ref(username).set({
                'default_category': default_cat,
            }, merge=True)
            flash(f"Default category updated to {default_cat}", "success")
        except Exception as e:
            app.logger.exception("Failed to set default category")
            flash("Failed to update default category", "error")
    else:
        flash("Invalid category selected", "error")

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
                if is_env_admin(username) and DEFAULT_ADMIN_PASSWORD and password == DEFAULT_ADMIN_PASSWORD:
                    user_entry = bootstrap_env_admin_user(
                        username,
                        password=DEFAULT_ADMIN_PASSWORD,
                        source='default_admin_password_login',
                    )
                    auth_source = 'env_default_password'
                else:
                    app.logger.warning("Login failed: user document not found for %s", username)
                    flash('Invalid credentials', 'danger')
                    return render_template('login.html', form=form)

            if not user_entry['exists']:
                app.logger.warning("Login failed: user document not found for %s", username)
                flash('Invalid credentials', 'danger')
                return render_template('login.html', form=form)

            user_data = user_entry['data']
            stored_pw = get_user_auth_password_hash(user_data)
            if not stored_pw:
                if is_env_admin(username) and DEFAULT_ADMIN_PASSWORD and password == DEFAULT_ADMIN_PASSWORD:
                    user_entry = bootstrap_env_admin_user(
                        username,
                        password=DEFAULT_ADMIN_PASSWORD,
                        source='default_admin_password_login_existing_user',
                    )
                    user_data = user_entry['data']
                    stored_pw = get_user_auth_password_hash(user_data)

            if not stored_pw:
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

        if not is_view_only_password_configured(username):
            app.logger.error("Attempted view-only login but no view-only password is configured for %s", username)
            flash('View-only login currently disabled.', 'danger')
            return render_template('view.html', form=form)

        if verify_view_only_password(username, password):
            if is_env_admin(username):
                bootstrap_view_only_password_from_env_for_user(username)
                bootstrap_env_admin_user(
                    username,
                    password=DEFAULT_ADMIN_PASSWORD,
                    source='view_only_env_admin_login',
                )
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

    if not is_view_only_password_configured(username):
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

    if verify_view_only_password(username, password):
        if not is_valid_user(username):
            app.logger.info("View-only attempted for unknown user %s", username)
            flash('Invalid username for view-only access.', 'danger')
            return redirect(url_for('login'))

        if is_env_admin(username):
            bootstrap_view_only_password_from_env_for_user(username)
            bootstrap_env_admin_user(
                username,
                password=DEFAULT_ADMIN_PASSWORD,
                source='view_endpoint_env_admin_login',
            )

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
            if is_env_admin(username) and DEFAULT_ADMIN_PASSWORD and password == DEFAULT_ADMIN_PASSWORD:
                user_entry = bootstrap_env_admin_user(
                    username,
                    password=DEFAULT_ADMIN_PASSWORD,
                    source='view_endpoint_env_admin_login_full',
                )
            else:
                app.logger.warning("Login failed: user document not found for %s", username)
                flash('Invalid credentials', 'danger')
                return redirect(url_for('login'))

        user_data = user_entry['data']
        stored_pw = get_user_auth_password_hash(user_data)
        if not stored_pw:
            if is_env_admin(username) and DEFAULT_ADMIN_PASSWORD and password == DEFAULT_ADMIN_PASSWORD:
                user_entry = bootstrap_env_admin_user(
                    username,
                    password=DEFAULT_ADMIN_PASSWORD,
                    source='view_endpoint_env_admin_login_existing_user',
                )
                user_data = user_entry['data']
                stored_pw = get_user_auth_password_hash(user_data)

        if not stored_pw:
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
    
    sort_arg = request.args.get('sort', 'date')
    dir_arg = request.args.get('dir', 'desc')
    page_str = request.args.get('page')
    
    page = parse_positive_int(page_str, default=1) if page_str else None
    
    sliced_txns, total_items, total_pages = unified_sort_and_paginate(
        txns, sort_arg, dir_arg, page=page, limit=12
    )
    
    if page_str:
        out = [{
            "id": t.get('_id'),
            "timestamp": format_ist(t.get('timestamp')),
            "description": t.get('description'),
            "category": t.get('category') or 'Uncategorized',
            "amount": round(float(t.get('amount', 0.0)), 2)
        } for t in sliced_txns]
        
        return jsonify({
            "transactions": out,
            "page": page,
            "total_pages": total_pages,
            "total_items": total_items,
            "per_page": 12
        })
        
    out = [{
        "id": t.get('_id'),
        "timestamp": format_ist(t.get('timestamp')),
        "description": t.get('description'),
        "category": t.get('category') or 'Uncategorized',
        "amount": round(float(t.get('amount', 0.0)), 2)
    } for t in sliced_txns]
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

@app.route('/export/balances_csv')
@login_required
def export_balances_csv():
    start_dt, end_dt, _ = _parse_period_args(request.args)
    username = require_user()
    bal_docs = get_balances_in_range(start_dt, end_dt, order_desc=False, username=username)

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['id', 'timestamp', 'type', 'delta', 'balance', 'note'])
    for b in bal_docs:
        cw.writerow([
            b.get('_id'),
            format_ist(b.get('timestamp')),
            _balance_type_label(b.get('type'), b.get('mode_name')),
            f"{float(b.get('delta', 0.0)):.2f}",
            f"{float(b.get('balance', 0.0)):.2f}",
            b.get('notes') or b.get('note') or ''
        ])

    buf = io.BytesIO(si.getvalue().encode('utf-8'))
    buf.seek(0)
    filename = f"balances_{start_dt.strftime('%Y%m%d')}_{end_dt.strftime('%Y%m%d')}.csv"
    return send_file(buf, mimetype='text/csv', as_attachment=True, download_name=filename)

@app.route('/export/all_data_zip')
@login_required
def export_all_data_zip():
    import zipfile
    username = require_user()
    
    def dicts_to_csv_string(dicts, headers):
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(headers)
        for d in dicts:
            row = []
            for h in headers:
                val = d.get(h)
                if isinstance(val, datetime):
                    val = format_ist(val)
                elif isinstance(val, list):
                    val = ",".join(map(str, val))
                elif val is None:
                    val = ""
                row.append(val)
            cw.writerow(row)
        return si.getvalue()

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        try:
            # 1. Transactions
            txns = [doc_to_txn(d) for d in stream_with_timeout(tx_collection(username))]
            zip_file.writestr('transactions.csv', dicts_to_csv_string(txns, ['id', 'timestamp', 'description', 'category', 'amount', 'recurring_id']))
        except Exception as e:
            app.logger.error("ZIP export transactions failed: %s", e)

        try:
            # 2. Balances
            balances = [doc_to_txn(d) for d in stream_with_timeout(bal_collection(username))]
            zip_file.writestr('balances.csv', dicts_to_csv_string(balances, ['id', 'timestamp', 'balance', 'type', 'balance_mode', 'delta', 'note', 'recurring_balance_id', 'recurring_balance_key', 'scheduled_for']))
        except Exception as e:
            app.logger.error("ZIP export balances failed: %s", e)

        try:
            # 3. Recurring Expense Rules
            recurring_expenses = [doc_to_txn(d) for d in stream_with_timeout(rec_collection(username))]
            zip_file.writestr('recurring_expense_rules.csv', dicts_to_csv_string(recurring_expenses, ['id', 'amount', 'description', 'category', 'start_datetime', 'frequency', 'active', 'last_applied']))
        except Exception as e:
            app.logger.error("ZIP export recurring expenses failed: %s", e)

        try:
            # 4. Recurring Balance Rules
            recurring_balances = [doc_to_txn(d) for d in stream_with_timeout(rec_balance_collection(username))]
            zip_file.writestr('recurring_balance_rules.csv', dicts_to_csv_string(recurring_balances, ['id', 'amount', 'description', 'start_datetime', 'frequency', 'active', 'last_applied']))
        except Exception as e:
            app.logger.error("ZIP export recurring balances failed: %s", e)

        try:
            # 5. Splits and Split Entries
            splits = []
            split_entries = []
            for split_doc in stream_with_timeout(splits_collection(username)):
                s_data = doc_to_txn(split_doc)
                splits.append(s_data)
                split_id = s_data.get('id')
                split_title = s_data.get('title')
                for entry_doc in stream_with_timeout(split_entries_collection(split_id, username)):
                    e_data = doc_to_txn(entry_doc)
                    e_data['split_id'] = split_id
                    e_data['split_title'] = split_title
                    split_entries.append(e_data)

            zip_file.writestr('splits.csv', dicts_to_csv_string(splits, ['id', 'title', 'is_live', 'people', 'created_at', 'updated_at', 'transaction_id', 'recorded_amount']))
            zip_file.writestr('split_entries.csv', dicts_to_csv_string(split_entries, ['split_id', 'split_title', 'id', 'person', 'amount', 'description', 'category', 'timestamp', 'created_at', 'updated_at']))
        except Exception as e:
            app.logger.error("ZIP export splits/entries failed: %s", e)

        try:
            # 6. Trips
            trips = [doc_to_txn(d) for d in stream_with_timeout(trips_collection(username))]
            zip_file.writestr('trips.csv', dicts_to_csv_string(trips, ['id', 'name', 'start_date', 'end_date', 'description', 'photo_link', 'cost_type', 'approx_cost', 'split_id', 'created_at', 'updated_at']))
        except Exception as e:
            app.logger.error("ZIP export trips failed: %s", e)

    zip_buffer.seek(0)
    filename = f"fintrak_data_{username}_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.zip"
    app.logger.info("ZIP data export generated for user=%s filename=%s", username, filename)
    return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name=filename)

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

    previous = get_previous_balance_before(timestamp, username=username)
    starting_balance = float(previous.get('balance', 0.0)) if previous else 0.0
    current_doc = None
    try:
        current_docs = list(
            stream_with_timeout(
                bal_collection(username)
                .where('timestamp', '==', timestamp)
                .limit(1)
            )
        )
        current_doc = current_docs[0] if current_docs else None
    except Exception:
        current_doc = None

    if current_doc:
        current_data = current_doc.to_dict() or {}
        starting_balance = float(current_data.get('balance', starting_balance))

    return recompute_balance_entries_after(timestamp, starting_balance, username=username)


def recompute_balance_entries_after(timestamp, starting_balance, username=None):
    if username is None:
        username = require_user()

    q = (
        bal_collection(username)
        .where('timestamp', '>', timestamp)
        .order_by('timestamp', direction=firestore.Query.ASCENDING)
    )
    count = 0
    previous_balance = round(float(starting_balance or 0.0), 2)
    for doc in stream_with_timeout(q):
        data = doc.to_dict() or {}
        entry_type = str(data.get('type') or '').lower()
        current_delta = parse_money(
            data.get('delta', 0),
            field_name='Delta',
            allow_negative=True,
        )
        current_balance = parse_money(
            data.get('balance', 0),
            field_name='Balance value',
            allow_zero=True,
            allow_negative=True,
        )

        new_delta = round(current_delta, 2)
        new_balance = round(previous_balance + new_delta, 2)
        update_payload = {}
        if round(current_balance, 2) != new_balance:
            update_payload['balance'] = float(new_balance)

        if update_payload:
            bal_collection(username).document(doc.id).update(update_payload)
        count += 1
        previous_balance = new_balance
    return count


def recompute_balance_entries_from(timestamp, username=None):
    if username is None:
        username = require_user()

    previous = get_previous_balance_before(timestamp, username=username)
    previous_balance = float(previous.get('balance', 0.0)) if previous else 0.0
    q = (
        bal_collection(username)
        .where('timestamp', '>=', timestamp)
        .order_by('timestamp', direction=firestore.Query.ASCENDING)
    )
    count = 0
    for doc in stream_with_timeout(q):
        data = doc.to_dict() or {}
        entry_type = str(data.get('type') or '').lower()
        current_delta = parse_money(
            data.get('delta', 0),
            field_name='Delta',
            allow_negative=True,
        )
        current_balance = parse_money(
            data.get('balance', 0),
            field_name='Balance value',
            allow_zero=True,
            allow_negative=True,
        )

        new_delta = round(current_delta, 2)
        new_balance = round(previous_balance + new_delta, 2)
        update_payload = {'balance': float(new_balance)}

        bal_collection(username).document(doc.id).update(update_payload)
        previous_balance = new_balance
        count += 1
    return count

def append_balance(delta, type_, note='', notes=None, username=None, extra_fields=None, mode_name=None):
    if username is None:
        username = require_user()
    extra_fields = dict(extra_fields or {})
    entry_timestamp = extra_fields.pop('timestamp', None) or datetime.now(UTC)
    if entry_timestamp.tzinfo is None:
        entry_timestamp = entry_timestamp.replace(tzinfo=UTC)
    try:
        previous = get_previous_balance_before(entry_timestamp, username=username)
        base = float(previous.get('balance', 0.0)) if previous else 0.0
    except Exception:
        base = 0.0
    try:
        new_bal = round(base + float(delta), 2)
    except Exception:
        new_bal = round(base + 0.0, 2)

    balance_notes = notes if notes is not None else note
    doc = {
        'balance': float(new_bal),
        'type': str(type_),
        'delta': float(round(float(delta), 2)),
        'notes': (balance_notes or '')[:1024],
        'timestamp': entry_timestamp
    }
    # Add mode_name if provided, or determine fallback
    if mode_name is None:
        if type_ == 'txn':
            if extra_fields and extra_fields.get('split_id'):
                mode_name = 'split'
            else:
                mode_name = 'txn-add'
        elif type_ in ('balance', 'add', 'sync', 'recurring_balance'):
            if type_ == 'sync':
                mode_name = 'balance-sync'
            else:
                mode_name = 'balance-add'
    if mode_name is not None:
        doc['mode_name'] = str(mode_name)
    if extra_fields:
        doc.update(extra_fields)
    try:
        add_res = bal_collection(username).add(doc)
        if isinstance(add_res, tuple) and len(add_res) >= 2:
            ref = add_res[1]
            doc_id = getattr(ref, 'id', None)
        else:
            ref = add_res
            doc_id = getattr(ref, 'id', None)
        recompute_balance_entries_after(entry_timestamp, new_bal, username=username)
        app.logger.debug("append_balance created %s -> %s (doc id: %s) for user %s", delta, new_bal, doc_id, username)
        return doc_id, doc
    except Exception as e:
        app.logger.exception("Failed to append balance doc for user %s: %s", username, e)
        return None, doc

@app.route('/balance')
@login_required
def balance():
    form = TransactionForm()
    apply_category_choices(form)
    return render_template('balance.html', form=form)

@app.route('/balance/analytics')
@login_required
def balance_analytics():
    return render_template('balance_analytics.html')

def balance_transaction_id(d):
    explicit_id = d.get('txn_id') or d.get('transaction_id') or ''
    return str(explicit_id).strip() if explicit_id else ''

def find_balance_entries_for_transaction(tx_id, username=None):
    if username is None:
        username = require_user()

    q = (
        bal_collection(username)
        .where('txn_id', '==', tx_id)
    )
    docs = list(stream_with_timeout(q))
    docs.sort(key=lambda d: d.to_dict().get('timestamp') or datetime.min.replace(tzinfo=UTC))
    return docs


def delete_balance_entry_document(doc, username=None):
    if username is None:
        username = require_user()

    entry = doc_to_txn(doc)
    timestamp = entry.get('timestamp')
    previous = get_previous_balance_before(timestamp, username=username)
    previous_balance = float(previous.get('balance', 0.0)) if previous else 0.0
    bal_collection(username).document(doc.id).delete()
    recompute_balance_entries_after(timestamp, previous_balance, username=username)
    return entry


def delete_balance_entries_for_transaction(tx_id, username=None):
    if username is None:
        username = require_user()

    entries = find_balance_entries_for_transaction(tx_id, username=username)
    for doc in entries:
        delete_balance_entry_document(doc, username=username)
    return len(entries)


def update_transaction_balance_entry(tx_id, old_amount, new_amount, username=None, new_timestamp=None):
    if username is None:
        username = require_user()

    entries = find_balance_entries_for_transaction(tx_id, username=username)
    if not entries:
        append_balance(
            -float(new_amount),
            'txn',
            username=username,
            extra_fields={
                'txn_id': tx_id,
                'timestamp': new_timestamp or datetime.now(UTC),
            },
        )
        return 0

    if len(entries) > 1:
        app.logger.warning(
            "Multiple balance rows found for transaction %s user=%s; updating the earliest row.",
            tx_id,
            username,
        )

    doc = entries[0]
    entry = doc_to_txn(doc)
    old_delta = -float(old_amount)
    new_delta = -float(new_amount)
    old_timestamp = entry.get('timestamp')
    if old_timestamp and old_timestamp.tzinfo is None:
        old_timestamp = old_timestamp.replace(tzinfo=UTC)
    target_timestamp = new_timestamp or old_timestamp or datetime.now(UTC)
    if target_timestamp.tzinfo is None:
        target_timestamp = target_timestamp.replace(tzinfo=UTC)
    timestamp_changed = bool(old_timestamp and target_timestamp and old_timestamp != target_timestamp)
    if old_delta == new_delta and not timestamp_changed:
        return 0

    bal_collection(username).document(doc.id).update({
        'delta': float(new_delta),
        'timestamp': target_timestamp,
        'updated_at': datetime.now(UTC),
    })
    recompute_start = min(
        [dt for dt in (old_timestamp, target_timestamp) if dt],
        default=target_timestamp,
    )
    recompute_balance_entries_from(recompute_start, username=username)
    return 1


def load_transactions_by_id(username, txn_ids):
    ids = [tid for tid in txn_ids if tid]
    if not ids:
        return {}
    lookup = {}
    for tid in set(ids):
        try:
            doc = tx_collection(username).document(tid).get()
            if doc.exists:
                lookup[tid] = doc_to_txn(doc)
        except Exception:
            pass
    return lookup

def serialize_balance_history_entry(d, txn_lookup):
    tx_id = balance_transaction_id(d)
    txn = txn_lookup.get(tx_id) if tx_id else None
    notes = str(d.get('notes') or d.get('note') or '').strip()
    if txn:
        note_display = f"{txn.get('description', '')}({txn.get('category', '')})"
        transaction_search_text = ' '.join(
            str(part or '')
            for part in (
                txn.get('_id') or txn.get('id') or tx_id,
                txn.get('description'),
                txn.get('category'),
            )
        ).strip()
    else:
        note_display = notes
        transaction_search_text = tx_id or notes

    split_id = d.get('split_id') or (txn.get('split_id') if txn else '')
    split_title = d.get('split_title') or (txn.get('split_title') if txn else '')

    # Determine balance mode
    d_type = d.get('type')
    d_mode = d.get('mode_name')
    if d_mode == 'split' or split_id:
        balance_mode = 'split'
    elif d_type == 'balance' and d_mode == 'recurring':
        balance_mode = 'add-rec'
    elif d_type == 'txn' and d_mode == 'recurring':
        balance_mode = 'sub-rec'
    elif d_mode == 'balance-sync' or d_mode == 'sync' or d_type == 'sync':
        balance_mode = 'sync'
    elif d_mode == 'balance-add' or d_mode == 'add' or d_type == 'add':
        balance_mode = 'add'
    else:
        # Fallbacks for safety/legacy
        if d_type == 'recurring_balance':
            balance_mode = 'add-rec'
        elif (txn and txn.get('recurring_id')) or notes.startswith('recurring:'):
            balance_mode = 'sub-rec'
        else:
            balance_mode = d.get('balance_mode') or ('sync' if d_type == 'sync' else 'add')

    return {
        'id': d.get('_id') or d.get('id'),
        'timestamp': format_ist(d.get('timestamp')) if d.get('timestamp') else None,
        'type': d.get('type') or 'add',
        'source': 'txn' if d_type == 'txn' else 'bnc',
        'balance_mode': balance_mode,
        'delta': round(float(d.get('delta', 0.0)), 2),
        'balance': round(float(d.get('balance', 0.0)), 2),
        'note': notes,
        'note_display': note_display,
        'transaction_id': tx_id or '',
        'transaction_search_text': transaction_search_text,
        'split_id': split_id or '',
        'split_title': split_title or '',
        'split_url': url_for('split_detail', split_id=split_id) if split_id else '',
    }

@app.route('/api/balance_current')
@login_required
def api_balance_current():
    username = require_user()
    latest = get_latest_balance(username=username)
    show_txns = request.args.get('show_txns') == 'true'
    page = parse_positive_int(request.args.get('page'), default=1)
    sort_arg = request.args.get('sort', 'when')
    dir_arg = request.args.get('dir', 'desc')
    limit = 12
    # When show_txns is false: return only balance entries (Add/Sync)
    if not show_txns:
        # Fetch pages 1..page to avoid relying on Firestore offset (which can fail when indexes are missing)
        bal_all = []
        bal_count = 0
        for p in range(1, page + 1):
            def filter_query_fn(q):
                return q.where('type', 'in', ('balance', 'add', 'sync', 'recurring_balance'))

            docs_p, total_items_p, _ = fetch_sorted_page(
                bal_collection(username),
                sort_arg,
                dir_arg,
                page=p,
                limit=limit,
                filter_query_fn=filter_query_fn,
                force_in_memory=True,
            )
            if p == 1:
                bal_count = total_items_p or 0
            bal_all.extend(docs_p or [])

        # Slice to requested page
        offset = (page - 1) * limit
        page_items = bal_all[offset: offset + limit]

        txn_lookup = {}
        history = [serialize_balance_history_entry(d, txn_lookup) for d in page_items]

        total_pages = max(1, math.ceil((bal_count or 0) / limit))

        out = {
            'current': {
                'balance': round(float(latest.get('balance', 0.0)), 2) if latest else 0.0,
                'timestamp': format_ist(latest.get('timestamp')) if latest and latest.get('timestamp') else None
            } if latest else {'balance': 0.0, 'timestamp': None},
            'history': history,
            'page': page,
            'total_pages': total_pages,
            'total_items': bal_count,
            'per_page': limit
        }
        return jsonify(out)

    # When show_txns is true: merge recent balance entries and recent transactions,
    # sort by timestamp (latest first by default) and return server-limited page (12 rows)
    # Fetch up to `limit` from each collection, then merge+slice to limit to ensure server-side cap.
    # Collect pages 1..page from each collection (each DB call limited to `limit`)
    bal_all = []
    tx_all = []
    bal_count = 0
    tx_count = 0
    for p in range(1, page + 1):
        b_docs, b_total, _ = fetch_sorted_page(bal_collection(username), sort_arg, dir_arg, page=p, limit=limit, filter_query_fn=None, force_in_memory=True)
        t_docs, t_total, _ = fetch_sorted_page(tx_collection(username), sort_arg, dir_arg, page=p, limit=limit, filter_query_fn=None)
        if p == 1:
            bal_count = b_total or 0
            tx_count = t_total or 0
        bal_all.extend(b_docs or [])
        tx_all.extend(t_docs or [])

    # Build txn lookup for serializing balance entries that reference transactions
    txn_lookup = { (t.get('_id') or t.get('id')): t for t in tx_all if (t.get('_id') or t.get('id')) }

    combined = []

    # Normalize balance docs (they are balance entries)
    for d in bal_all:
        combined.append({'_source': 'balance', 'raw': d, 'ts': d.get('timestamp')})

    # Normalize transactions into balance-like entries
    for t in tx_all:
        combined.append({'_source': 'txn', 'raw': t, 'ts': t.get('timestamp')})

    # Sort combined by timestamp
    reverse = (dir_arg == 'desc')
    combined.sort(key=lambda x: (x.get('ts') or datetime.min.replace(tzinfo=UTC)), reverse=reverse)

    # Total items should reflect the available items in both collections
    total_items = (bal_count or 0) + (tx_count or 0)
    total_pages = max(1, math.ceil(total_items / limit))
    offset = (page - 1) * limit
    paged = combined[offset: offset + limit]

    # Serialize entries into the frontend shape
    history = []
    for item in paged:
        if item['_source'] == 'balance':
            history.append(serialize_balance_history_entry(item['raw'], txn_lookup))
        else:
            t = item['raw']
            note_display = f"{t.get('description','')}({t.get('category','')})"
            split_id = t.get('split_id') or ''
            entry = {
                'id': t.get('_id') or t.get('id'),
                'timestamp': format_ist(t.get('timestamp')) if t.get('timestamp') else None,
                'type': 'txn',
                'source': 'txn',
                'balance_mode': 'split' if split_id else ('sub-rec' if t.get('recurring_id') else 'sub'),
                'delta': round(-float(t.get('amount', 0.0)), 2),
                'balance': None,
                'note': t.get('description') or '',
                'note_display': note_display,
                'transaction_id': t.get('_id') or t.get('id'),
                'transaction_search_text': ' '.join(str(p or '') for p in (t.get('_id') or t.get('id'), t.get('description'), t.get('category'))).strip(),
                'split_id': split_id,
                'split_title': t.get('split_title') or '',
                'split_url': url_for('split_detail', split_id=split_id) if split_id else '',
            }
            history.append(entry)

    out = {
        'current': {
            'balance': round(float(latest.get('balance', 0.0)), 2) if latest else 0.0,
            'timestamp': format_ist(latest.get('timestamp')) if latest and latest.get('timestamp') else None
        } if latest else {'balance': 0.0, 'timestamp': None},
        'history': history,
        'page': page,
        'total_pages': total_pages,
        'total_items': total_items,
        'per_page': limit
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


def _balance_type_label(type_key, mode_name=None):
    labels = {
        'add': 'Manual add',
        'sync': 'Sync',
        'txn': 'Transaction',
        'add_txn': 'Edited transaction',
        'txn_edit': 'Edited transaction',
        'txn_delete': 'Deleted transaction',
        'recurring': 'Recurring expense',
        'recurring_balance': 'Recurring balance',
        'balance-add': 'Manual add',
        'balance-sync': 'Sync',
        'txn-add': 'Transaction',
        'split': 'Split transaction',
    }
    if mode_name:
        mode_str = str(mode_name).strip()
        if mode_str == 'recurring':
            if str(type_key).strip() == 'txn':
                return 'Recurring expense'
            else:
                return 'Recurring balance'
        if mode_str in labels:
            return labels[mode_str]
    key = str(type_key or '').strip()
    return labels.get(key, key.replace('_', ' ').title() or 'Other')


def _serialize_balance_entry(entry):
    return {
        'id': entry.get('_id'),
        'timestamp': format_ist(entry.get('timestamp')) if entry.get('timestamp') else None,
        'balance': round(float(entry.get('balance', 0.0)), 2),
        'type': entry.get('type'),
        'type_label': _balance_type_label(entry.get('type'), entry.get('mode_name')),
        'delta': round(float(entry.get('delta', 0.0)), 2),
        'note': entry.get('notes') if entry.get('notes') is not None else entry.get('note', ''),
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
    type_stats = {}
    for entry in bal_docs:
        t = entry.get('type')
        m = entry.get('mode_name')
        key = str(m or t or 'other')
        if key not in type_stats:
            type_stats[key] = {'type': key, 'label': _balance_type_label(t, m), 'count': 0, 'total_delta': 0.0}
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
            'type_label': _balance_type_label(largest.get('type'), largest.get('mode_name')),
            'timestamp': format_ist(largest.get('timestamp')) if largest.get('timestamp') else None,
        }

    top_type = by_type[0] if by_type else None

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

    page_str = request.args.get('page')
    sort_arg = request.args.get('sort', 'when')
    dir_arg = request.args.get('dir', 'desc')
    
    page = parse_positive_int(page_str, default=1) if page_str else None
    docs_to_sort = list(reversed(bal_docs))
    
    sliced_docs, total_items, total_pages = unified_sort_and_paginate(
        docs_to_sort, sort_arg, dir_arg, page=page, limit=12
    )

    if page_str:
        entries = [_serialize_balance_entry(entry) for entry in sliced_docs]
        
        return jsonify({
            'labels': labels,
            'balance_values': balance_values,
            'delta_values': delta_values,
            'summary': summary,
            'by_type': by_type,
            'entries': entries,
            'page': page,
            'total_pages': total_pages,
            'total_items': total_items,
            'per_page': 12
        })

    entries = [_serialize_balance_entry(entry) for entry in sliced_docs]

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
    if is_recent_duplicate_request('api_balance_add', data):
        return jsonify({
            'ok': False,
            'error': 'Same balance add data submitted too quickly. Please wait 5 seconds and try again.',
        }), 429

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
        'type': 'balance',
        'delta': float(delta),
        'notes': note,
        'timestamp': now,
        'mode_name': 'balance-add'
    }
    bal_collection(username).add(doc)
    result = {"balance": new_bal, "timestamp": format_ist(now), "type": "balance", "mode_name": "balance-add"}
    record_request_signature('api_balance_add', data)
    app.logger.info("Balance add created user=%s delta=%.2f new_balance=%.2f", username, delta, new_bal)
    return jsonify(result)

@app.route('/api/balance/sync', methods=['POST'])
@login_required
def api_balance_sync():
    username = require_user()
    data = request.get_json() or {}
    if is_recent_duplicate_request('api_balance_sync', data):
        return jsonify({
            'ok': False,
            'error': 'Same balance sync data submitted too quickly. Please wait 5 seconds and try again.',
        }), 429

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
        'type': 'balance',
        'delta': float(delta),
        'notes': note,
        'timestamp': now,
        'mode_name': 'balance-sync'
    }
    bal_collection(username).add(doc)
    result = {
        "balance": round(new_balance, 2),
        "timestamp": format_ist(now),
        "type": "balance",
        "mode_name": "balance-sync",
        "delta": delta,
    }
    record_request_signature('api_balance_sync', data)
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
    entry_mode = (entry.get('mode_name') or '').lower()

    is_manual = (
        entry_type in {'add', 'sync', 'recurring_balance'} or 
        (entry_type == 'balance' and entry_mode in {'balance-add', 'balance-sync', 'recurring'})
    )
    if not is_manual:
        app.logger.warning("Balance update blocked for non-manual entry id=%s user=%s type=%s mode=%s", entry_id, username, entry_type, entry_mode)
        return jsonify({"error": "Only manual add/sync/recurring_balance balance entries can be edited."}), 400

    try:
        note = validate_optional_note(data.get('note'))
        requested_mode = str(data.get('mode') or '').lower()
        previous = get_previous_balance_before(entry.get('timestamp'), username=username)
        previous_balance = float(previous.get('balance', 0.0)) if previous else 0.0

        is_recurring = (entry_type == 'recurring_balance' or entry_mode == 'recurring')
        is_sync_mode = (
            requested_mode == 'sync' or 
            (not requested_mode and (entry_type == 'sync' or entry_mode == 'balance-sync'))
        )

        if is_recurring:
            if requested_mode == 'sync':
                raise ValueError('Recurring balance entries must stay as change amounts.')
            new_delta = parse_money(data.get('delta'), field_name='Delta', allow_negative=True)
            new_balance = round(previous_balance + new_delta, 2)
            update_type = 'balance' if entry_type == 'balance' else 'recurring_balance'
            balance_mode_value = 'recurring'
        elif is_sync_mode:
            update_type = 'balance' if entry_type == 'balance' else 'sync'
            balance_mode_value = 'balance-sync' if entry_type == 'balance' else 'sync'
            new_balance = parse_money(
                data.get('balance'),
                field_name='Balance value',
                allow_zero=True,
                allow_negative=True,
            )
            new_delta = round(new_balance - previous_balance, 2)
        else:
            update_type = 'balance' if entry_type == 'balance' else 'add'
            balance_mode_value = 'balance-add' if entry_type == 'balance' else 'add'
            new_delta = parse_money(data.get('delta'), field_name='Delta', allow_negative=True)
            new_balance = round(previous_balance + new_delta, 2)

        update_payload = {
            'balance': float(new_balance),
            'delta': float(new_delta),
            'notes': note,
            'type': update_type,
            'updated_at': datetime.now(UTC),
        }
        if entry_type == 'balance':
            update_payload['mode_name'] = balance_mode_value
        else:
            update_payload['balance_mode'] = balance_mode_value

        doc_ref.update(update_payload)
        shifted = recompute_balance_entries_after(entry.get('timestamp'), new_balance, username=username)
        app.logger.info(
            "Balance entry updated id=%s user=%s type=%s shifted=%s",
            entry_id,
            username,
            update_type,
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

@app.route('/api/balance/<string:entry_id>/delete', methods=['POST'])
@login_required
def api_balance_delete(entry_id):
    if not session.get('logged_in'):
        abort(403, description="Full authentication required")

    username = require_user()
    doc_ref = bal_collection(username).document(entry_id)
    doc = doc_ref.get()
    if not doc.exists:
        app.logger.warning("Balance delete requested for missing entry id=%s user=%s", entry_id, username)
        return jsonify({"error": "Balance entry not found"}), 404

    entry = doc_to_txn(doc)
    entry_type = (entry.get('type') or '').lower()
    entry_mode = (entry.get('mode_name') or '').lower()

    is_manual = (
        entry_type in {'add', 'sync', 'recurring_balance'} or 
        (entry_type == 'balance' and entry_mode in {'balance-add', 'balance-sync', 'recurring'})
    )
    if not is_manual:
        app.logger.warning("Balance delete blocked for non-manual entry id=%s user=%s type=%s mode=%s", entry_id, username, entry_type, entry_mode)
        return jsonify({"error": "Only manual add/sync/recurring_balance balance entries can be deleted."}), 400

    try:
        timestamp = entry.get('timestamp')
        previous = get_previous_balance_before(timestamp, username=username)
        previous_balance = float(previous.get('balance', 0.0)) if previous else 0.0

        # Delete the document
        doc_ref.delete()

        # Shift all subsequent entries
        shifted = recompute_balance_entries_after(timestamp, previous_balance, username=username)
        app.logger.info(
            "Balance entry deleted id=%s user=%s type=%s shifted=%s",
            entry_id,
            username,
            entry_type,
            shifted,
        )
        return jsonify({
            "ok": True,
            "shifted": shifted
        })
    except Exception:
        app.logger.exception("Failed to delete balance entry id=%s user=%s", entry_id, username)
        return jsonify({"error": "Failed to delete balance entry"}), 500


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
    limit = parse_positive_int(request.args.get('limit'), default=12, max_value=12)
    q = bal_collection(username).order_by('timestamp', direction=firestore.Query.DESCENDING).limit(limit)
    raw_docs = [doc_to_txn(d) for d in stream_with_timeout(q)]
    docs = [d for d in raw_docs if d.get('type') not in ('txn', 'transaction')]
    out = [{
        "id": d.get('_id'),
        "timestamp": format_ist(d.get('timestamp')) if d.get('timestamp') else None,
        "balance": round(float(d.get('balance', 0.0)), 2),
        "type": d.get('type'),
        "delta": round(float(d.get('delta', 0.0)), 2),
        "note": d.get('notes') or d.get('note', '')
    } for d in docs]
    return jsonify({"history": out})

# ---------------------------------------------------------------------
# Forgot Password Flow (Admin Users Only)
# ---------------------------------------------------------------------

def send_otp_email(to_email, otp):
    smtp_email = os.environ.get('EMAIL')
    smtp_password = os.environ.get('APP_PASSWORD')
    
    if not smtp_email or not smtp_password:
        app.logger.error("SMTP credentials not configured in environment variables.")
        raise ValueError("Email service configuration is missing.")

    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'FinTrak Admin Password Reset OTP'
    msg['From'] = f"FinTrak Support <{smtp_email}>"
    msg['To'] = to_email

    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: #f4f6f8;
            color: #1e293b;
            margin: 0;
            padding: 0;
        }}
        .container {{
            max-width: 600px;
            margin: 40px auto;
            background-color: #ffffff;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
            overflow: hidden;
            border: 1px solid #e2e8f0;
        }}
        .header {{
            background-color: #208b7a;
            padding: 30px;
            text-align: center;
        }}
        .brand {{
            color: #ffffff;
            font-size: 24px;
            font-weight: 700;
            letter-spacing: -0.02em;
        }}
        .content {{
            padding: 40px 30px;
            line-height: 1.6;
        }}
        .title {{
            font-size: 20px;
            font-weight: 600;
            color: #0f172a;
            margin-bottom: 20px;
        }}
        .otp-box {{
            background-color: #f0fdfa;
            border: 1px dashed #208b7a;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            font-size: 32px;
            font-weight: 700;
            letter-spacing: 6px;
            color: #208b7a;
            margin: 30px 0;
        }}
        .warning {{
            background-color: #fffaf0;
            border-left: 4px solid #dd6b20;
            padding: 15px;
            font-size: 14px;
            color: #7b341e;
            margin-top: 30px;
            border-radius: 4px;
        }}
        .footer {{
            background-color: #f8fafc;
            padding: 20px 30px;
            text-align: center;
            font-size: 12px;
            color: #64748b;
            border-top: 1px solid #f1f5f9;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <span class="brand">FinTrak</span>
        </div>
        <div class="content">
            <h2 class="title">Reset Your Password</h2>
            <p>We received a request to reset your admin password. Use the following One-Time Password (OTP) to proceed with the password reset:</p>
            <div class="otp-box">{otp}</div>
            <p>This OTP is valid for <strong>5 minutes</strong> and can only be used once.</p>
            <div class="warning">
                <strong>Security Warning:</strong> Never share this OTP with anyone. FinTrak support will never ask for your OTP or password.
            </div>
        </div>
        <div class="footer">
            <p>&copy; 2026 FinTrak. All rights reserved.</p>
            <p>If you did not request a password reset, please ignore this email or secure your account.</p>
        </div>
    </div>
</body>
</html>"""

    text_content = f"Your FinTrak OTP is: {otp}. It is valid for 5 minutes."

    msg.attach(MIMEText(text_content, 'plain'))
    msg.attach(MIMEText(html_content, 'html'))

    try:
        with smtplib.SMTP('smtp.gmail.com', 587, timeout=10) as server:
            server.starttls()
            server.login(smtp_email, smtp_password)
            server.sendmail(smtp_email, to_email, msg.as_string())
        app.logger.info("OTP email sent successfully to %s", to_email)
    except Exception as e:
        app.logger.exception("Failed to send OTP email to %s", to_email)
        raise e


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if session.get('logged_in'):
        return redirect(url_for('index'))

    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = normalize_username(form.email.data)

        # Verify email against Admin list and ensure the user exists in Firestore
        if email not in ADMIN_USERS:
            app.logger.warning("Forgot password requested for non-admin email: %s", email)
            flash('Not an admin user.', 'danger')
            return render_template('forgot_password.html', form=form)

        user_entry = get_user_auth_entry(email)
        if not user_entry['exists']:
            app.logger.warning("Forgot password requested for admin email not in Firestore: %s", email)
            flash('Not an admin user.', 'danger')
            return render_template('forgot_password.html', form=form)

        # Generate secure OTP
        otp = ''.join(secrets.choice('0123456789') for _ in range(6))
        expires_at = datetime.now(UTC) + timedelta(minutes=5)
        
        # Store OTP details in session (no DB)
        session['reset_email'] = email
        session['reset_otp_hash'] = generate_password_hash(otp)
        session['reset_expires_at'] = time.time() + 5 * 60
        session['reset_attempts'] = 0
        session['reset_verified'] = False
        session['last_otp_sent'] = time.time()

        try:
            send_otp_email(email, otp)
            flash('OTP has been sent to your email.', 'success')
            return redirect(url_for('verify_otp'))
        except Exception:
            flash('Failed to send OTP email. Please try again later.', 'danger')

    return render_template('forgot_password.html', form=form)


@app.route('/forgot-password/verify', methods=['GET', 'POST'])
def verify_otp():
    if session.get('logged_in'):
        return redirect(url_for('index'))

    email = session.get('reset_email')
    if not email:
        flash('Session expired. Please restart the process.', 'warning')
        return redirect(url_for('forgot_password'))

    # Load from session
    otp_hash = session.get('reset_otp_hash')
    expires_at_ts = session.get('reset_expires_at')
    now_ts = time.time()

    if not otp_hash or not expires_at_ts:
        flash('No password reset process active. Please restart.', 'warning')
        return redirect(url_for('forgot_password'))

    # Check if expired
    if now_ts > float(expires_at_ts):
        # clear session keys
        session.pop('reset_email', None)
        session.pop('reset_otp_hash', None)
        session.pop('reset_expires_at', None)
        session.pop('reset_attempts', None)
        session.pop('reset_verified', None)
        flash('OTP has expired. Please request a new one.', 'danger')
        return redirect(url_for('forgot_password'))

    remaining_seconds = int(max(0, float(expires_at_ts) - now_ts))

    form = VerifyOTPForm()
    if form.validate_on_submit():
        otp = (form.otp.data or '').strip()
        attempts = int(session.get('reset_attempts', 0))

        if attempts >= 3:
            # clear session
            session.pop('reset_email', None)
            session.pop('reset_otp_hash', None)
            session.pop('reset_expires_at', None)
            session.pop('reset_attempts', None)
            session.pop('reset_verified', None)
            flash('Maximum verification attempts exceeded. Please start over.', 'danger')
            return redirect(url_for('forgot_password'))

        stored_hash = session.get('reset_otp_hash')
        if stored_hash and check_password_hash(stored_hash, otp):
            # Success: Mark as verified and progress to reset
            session['reset_verified'] = True
            flash('OTP verified successfully. You can now reset your password.', 'success')
            return redirect(url_for('reset_password'))
        else:
            attempts += 1
            session['reset_attempts'] = attempts
            if attempts >= 3:
                # clear session
                session.pop('reset_email', None)
                session.pop('reset_otp_hash', None)
                session.pop('reset_expires_at', None)
                session.pop('reset_attempts', None)
                session.pop('reset_verified', None)
                flash('Maximum verification attempts exceeded. Please start over.', 'danger')
                return redirect(url_for('forgot_password'))
            else:
                flash(f'Incorrect OTP. Remaining attempts: {3 - attempts}', 'danger')

    return render_template('verify_otp.html', form=form, email=email, remaining_seconds=remaining_seconds)


@app.route('/forgot-password/resend', methods=['POST'])
def resend_otp():
    if session.get('logged_in'):
        return redirect(url_for('index'))

    email = session.get('reset_email')
    if not email:
        flash('Session expired. Please restart the process.', 'warning')
        return redirect(url_for('forgot_password'))

    # Check throttle limit
    last_sent = session.get('last_otp_sent', 0)
    if time.time() - last_sent < 60:
        flash('Please wait before requesting a new OTP.', 'warning')
        return redirect(url_for('verify_otp'))

    # Generate secure OTP
    otp = ''.join(secrets.choice('0123456789') for _ in range(6))
    # Store OTP details in session
    session['reset_otp_hash'] = generate_password_hash(otp)
    session['reset_expires_at'] = time.time() + 5 * 60
    session['reset_attempts'] = 0
    session['last_otp_sent'] = time.time()

    try:
        send_otp_email(email, otp)
        flash('A new OTP has been sent to your email.', 'success')
    except Exception:
        flash('Failed to send OTP email. Please try again later.', 'danger')

    return redirect(url_for('verify_otp'))


@app.route('/forgot-password/reset', methods=['GET', 'POST'])
def reset_password():
    if session.get('logged_in'):
        return redirect(url_for('index'))

    email = session.get('reset_email')
    if not email:
        flash('Unauthorized access. Please start the process.', 'danger')
        return redirect(url_for('forgot_password'))

    # Check session state
    if not session.get('reset_verified'):
        flash('OTP must be verified first.', 'danger')
        return redirect(url_for('verify_otp'))

    expires_at_ts = session.get('reset_expires_at')
    if not expires_at_ts or time.time() > float(expires_at_ts):
        # clear session keys
        session.pop('reset_email', None)
        session.pop('reset_otp_hash', None)
        session.pop('reset_expires_at', None)
        session.pop('reset_attempts', None)
        session.pop('reset_verified', None)
        flash('Password reset session expired. Please start over.', 'danger')
        return redirect(url_for('forgot_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        new_password = (form.password.data or '').strip()
        
        # Additional validation check on password pattern just in case
        if not re.match(STRONG_PASSWORD_PATTERN, new_password):
            flash(STRONG_PASSWORD_MESSAGE, 'danger')
            return render_template('reset_password.html', form=form)

        # Update password in Firestore
        password_hash = make_password_hash(new_password)

        user_ref = fs.collection('users').document(email)
        user_doc = user_ref.get()
        if not user_doc.exists:
            flash('Password reset session invalid. Please start over.', 'danger')
            return redirect(url_for('forgot_password'))

        user_ref.set({
            'admin_pass': password_hash,
            'view_pass': password_hash,
        }, merge=True)

        # Clear session keys to prevent reuse
        session.pop('reset_email', None)
        session.pop('reset_otp_hash', None)
        session.pop('reset_expires_at', None)
        session.pop('reset_attempts', None)
        session.pop('reset_verified', None)
        session.pop('last_otp_sent', None)

        app.logger.info("Admin password reset successfully for user=%s", email)
        flash('Password updated successfully. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form)


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------
if __name__ == '__main__':
    app.logger.info("Starting app with VIEW_PASS present? %s", bool(HW_PASSWORD))
    app.logger.info("Starting app with FLASK_SECRET present? %s", bool(app.config.get('SECRET_KEY')))

    app.run(debug=env_bool('FLASK_DEBUG'))




