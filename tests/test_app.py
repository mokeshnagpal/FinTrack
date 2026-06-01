import unittest
import json
from app import app


class AppRoutesTest(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    def test_root_redirects_to_login(self):
        resp = self.client.get('/', follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/login', resp.headers.get('Location', ''))

    def test_login_get_renders(self):
        resp = self.client.get('/login')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Username', resp.data)

    def test_view_login_get_renders(self):
        resp = self.client.get('/view-login')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'View-only', resp.data)

    def test_api_login_wake_status_returns_json(self):
        resp = self.client.get('/api/login_wake_status')
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertTrue(data.get('ok'))
        self.assertTrue(data.get('awake'))

    def test_api_login_password_cache_status_returns_json(self):
        resp = self.client.get('/api/login_password_cache_status?username=test')
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertTrue(data.get('ok'))
        self.assertIn('cache_available', data)

    def test_sync_status_requires_login(self):
        resp = self.client.get('/sync-status', follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/login', resp.headers.get('Location', ''))


if __name__ == '__main__':
    unittest.main()
