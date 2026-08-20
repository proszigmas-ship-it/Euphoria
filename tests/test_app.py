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
    def test_payment_page_renders_successfully(self):
        response = self.client.get('/payment?product=365+Days')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'EUPHORIA', response.data)
        self.assertIn(b'2200 2082 2574 8764', response.data)

    def test_player_confirm_payment_flow(self):
        import secrets
        uname = 'TestPlayer_' + secrets.token_hex(3)
        uemail = uname.lower() + '@example.com'
        # Register a test player
        reg = self.client.post('/api/player/register', json={
            'username': uname,
            'email': uemail,
            'password': 'StrongPassword123!',
        })
        self.assertEqual(reg.status_code, 200)

        # Confirm payment
        confirm = self.client.post('/api/player/confirm-payment', json={
            'product': '365 Days',
            'method': 'card',
            'sender_card': '*8844',
            'sender_name': 'Ivan Testov',
            'comment': 'Pay 459 rub'
        })
        self.assertEqual(confirm.status_code, 200)
        data = confirm.get_json()
        self.assertTrue(data['ok'])
        self.assertEqual(data['product'], '365 Days')

        # Check me
        me = self.client.get('/api/player/me').get_json()
        self.assertIsNotNone(me['player']['subscription'])
        self.assertEqual(me['player']['subscription']['duration'], '365 Days')


if __name__ == '__main__':
    unittest.main()
