import json
import os
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parent.parent


class TemplateCompileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault('FLASK_SECRET', 'test-secret-key-for-templates')
        os.environ.setdefault(
            'FIREBASE_CREDENTIALS',
            json.dumps(
                {
                    'type': 'service_account',
                    'project_id': 'fintrak-test',
                    'private_key_id': 'test',
                    'private_key': (
                        '-----BEGIN RSA PRIVATE KEY-----\n'
                        'MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/y7WuJMFmQnQ1bX6m3cHAp'
                        '-----END RSA PRIVATE KEY-----\n'
                    ),
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
        cls.app.app_context().push()

    @classmethod
    def tearDownClass(cls):
        for item in reversed(cls._patches):
            item.stop()

    def test_all_html_templates_compile(self):
        templates = sorted(
            str(path.relative_to(ROOT / 'templates')).replace('\\', '/')
            for path in (ROOT / 'templates').rglob('*.html')
        )
        self.assertGreaterEqual(len(templates), 14)
        for name in templates:
            with self.subTest(template=name):
                self.app.jinja_env.get_template(name)


if __name__ == '__main__':
    unittest.main()
