import json
import os
import re
import unittest
from unittest.mock import MagicMock, patch

from forms import (
    STRONG_PASSWORD_PATTERN,
    ChangePasswordForm,
    LoginForm,
    ViewPasswordForm,
)


class FormValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault('FLASK_SECRET', 'test-secret-key-for-forms')
        os.environ.setdefault(
            'FIREBASE_CREDENTIALS',
            json.dumps(
                {
                    'type': 'service_account',
                    'project_id': 'fintrak-test',
                    'private_key_id': 'test',
                    'private_key': '-----BEGIN RSA PRIVATE KEY-----\nTEST\n-----END RSA PRIVATE KEY-----\n',
                    'client_email': 'test@fintrak-test.iam.gserviceaccount.com',
                    'client_id': '123',
                    'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
                    'token_uri': 'https://oauth2.googleapis.com/token',
                }
            ),
        )

        cert_patch = patch('firebase_admin.credentials.Certificate', return_value=MagicMock())
        init_patch = patch('firebase_admin.initialize_app')
        client_patch = patch('firebase_admin.firestore.client', return_value=MagicMock())
        cls._patches = [cert_patch, init_patch, client_patch]
        for item in cls._patches:
            item.start()

        import app as fintrak_app

        cls.app = fintrak_app.app
        cls.app.config['WTF_CSRF_ENABLED'] = False
        cls.app.app_context().push()

    @classmethod
    def tearDownClass(cls):
        for item in reversed(cls._patches):
            item.stop()

    def test_strong_password_pattern_accepts_valid_password(self):
        self.assertTrue(re.match(STRONG_PASSWORD_PATTERN, 'Abcdef1'))

    def test_strong_password_pattern_rejects_short_password(self):
        self.assertFalse(re.match(STRONG_PASSWORD_PATTERN, 'abc1'))

    def test_login_form_requires_email_shape(self):
        form = LoginForm(data={'username': 'not-an-email', 'password': 'secret'})
        self.assertFalse(form.validate())

    def test_view_password_form_requires_matching_confirm(self):
        form = ViewPasswordForm(
            data={
                'current_password': 'Oldpass1',
                'password': 'Newpass1',
                'confirm_password': 'Different1',
            }
        )
        self.assertFalse(form.validate())

    def test_change_password_form_accepts_matching_passwords(self):
        form = ChangePasswordForm(
            data={
                'current_password': 'Oldpass1',
                'password': 'Newpass1',
                'confirm_password': 'Newpass1',
            }
        )
        self.assertTrue(form.validate())


if __name__ == '__main__':
    unittest.main()
