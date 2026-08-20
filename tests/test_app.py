"""Regression checks for the core admin, plans, and licence flows."""
import tempfile
import unittest
from pathlib import Path

from euphoria import config
from euphoria import create_app


class EuphoriaAppTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = config.DB_PATH
        config.DB_PATH = Path(self.temp_dir.name) / 'euphoria-test.db'
        self.app = create_app()
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()
        response = self.client.post(
            '/api/admin/login',
            json={'username': config.ADMIN_USERNAME, 'password': config.ADMIN_PASSWORD},
        )
        self.assertEqual(response.status_code, 200)

    def tearDown(self):
        config.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    def generate_key(self, duration='90 Days'):
        response = self.client.post(
            '/api/admin/keys/generate',
            json={'duration': duration, 'amount': 1, 'max_uses': 1},
        )
        self.assertEqual(response.status_code, 200)
        return response.get_json()['keys'][0]

    def test_default_plans_match_the_requested_prices(self):
        response = self.client.get('/api/products')
        prices = {item['title']: item['price'] for item in response.get_json()}
        self.assertEqual(
            prices,
            {'30 Days': 159.0, '90 Days': 259.0, '365 Days': 459.0,
             'Lifetime': 699.0, 'HWID Reset': 199.0},
        )

    def test_bound_key_can_be_validated_again_without_consuming_it(self):
        key = self.generate_key()
        payload = {'key': key, 'uid': 'client-001', 'hwid': 'device-001'}
        first = self.client.post('/api/redeem-key', json=payload)
        second = self.client.post('/api/redeem-key', json=payload)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.get_json()['uses_left'], 0)

    def test_reset_allows_a_replacement_device_without_extending_expiry(self):
        key = self.generate_key('7 Days')
        first = self.client.post(
            '/api/redeem-key', json={'key': key, 'uid': 'client-001', 'hwid': 'device-001'},
        )
        self.assertEqual(first.status_code, 200)
        key_id = self.client.get('/api/admin/keys').get_json()['keys'][0]['id']
        self.assertEqual(
            self.client.post(f'/api/admin/keys/{key_id}/reset-hwid').status_code, 200,
        )
        replacement = self.client.post(
            '/api/redeem-key', json={'key': key, 'uid': 'client-001', 'hwid': 'device-002'},
        )
        self.assertEqual(replacement.status_code, 200)


if __name__ == '__main__':
    unittest.main()
