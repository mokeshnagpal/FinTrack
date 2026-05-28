#!/usr/bin/env python3
"""
Create or update a Firestore user's password hash under users/{username}.password.
"""

import getpass
import json
import os

import firebase_admin
from dotenv import load_dotenv
from firebase_admin import credentials, firestore
from werkzeug.security import generate_password_hash


load_dotenv()

firebase_credentials_str = os.environ.get('FIREBASE_CREDENTIALS')
if not firebase_credentials_str:
    raise SystemExit('FIREBASE_CREDENTIALS is missing.')

firebase_credentials_dict = json.loads(firebase_credentials_str)
if 'private_key' in firebase_credentials_dict:
    firebase_credentials_dict['private_key'] = firebase_credentials_dict['private_key'].replace('\\n', '\n')

cred = credentials.Certificate(firebase_credentials_dict)
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)

fs = firestore.client()

ADMIN_USERS = {
    user.strip().lower()
    for user in os.environ.get('ADMIN_USER', '').split(',')
    if user.strip()
}


def check_user_exists(username):
    return fs.collection('users').document(username).get().exists


def set_password_hash(username, pw_hash):
    fs.collection('users').document(username).set({'password': pw_hash}, merge=True)
    print(f"Saved hashed password for user '{username}'.")


def main():
    print('Firestore User Password Setup\n')

    username = input('Username: ').strip().lower()
    if not username:
        print('Username is required.')
        return

    if username not in ADMIN_USERS:
        print(f"'{username}' is NOT listed in ADMIN_USER env variable.")
        return

    print(f"'{username}' is an admin user.")
    if check_user_exists(username):
        print(f"User '{username}' already exists; password will be updated.")
    else:
        print(f"User '{username}' does not exist; a new document will be created.")

    password = getpass.getpass('New password (hidden): ').strip()
    if not password:
        print('Password cannot be empty.')
        return

    confirm = getpass.getpass('Confirm password: ').strip()
    if password != confirm:
        print('Passwords do not match.')
        return

    try:
        set_password_hash(username, generate_password_hash(password))
    except Exception as exc:
        print('Error saving password:', exc)


if __name__ == '__main__':
    main()
