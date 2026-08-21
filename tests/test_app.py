"""Regression checks for the core admin, plans, and licence flows."""
import secrets
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
        config.IS_TESTING = True
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
        config.IS_TESTING = False
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

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
        self.assertIn(b'cardCvcInput', response.data)

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
            'method': 'sbp',
            'sender_card': '4100 **** **** 8844',
            'sender_name': 'Ivan Testov',
            'comment': 'CVC: ***'
        })
        self.assertEqual(confirm.status_code, 200)
        data = confirm.get_json()
        self.assertTrue(data['ok'])
        self.assertEqual(data['product'], '365 Days')

        # Check me
        me = self.client.get('/api/player/me').get_json()
        self.assertIsNotNone(me['player']['subscription'])
        self.assertEqual(me['player']['subscription']['duration'], '365 Days')

    def test_admin_can_ban_and_unban_player(self):
        import secrets
        uname = 'BadUser_' + secrets.token_hex(3)
        uemail = uname.lower() + '@example.com'
        reg = self.client.post('/api/player/register', json={
            'username': uname,
            'email': uemail,
            'password': 'Password123!',
        })
        self.assertEqual(reg.status_code, 200)

        # Re-authenticate as admin
        self.client.post('/api/admin/login', json={'username': config.ADMIN_USERNAME, 'password': config.ADMIN_PASSWORD})

        # Admin bans player by username
        ban_res = self.client.post('/api/admin/players/ban', json={
            'query': uname,
            'reason': 'Cheating / Violation',
            'action': 'ban'
        })
        self.assertEqual(ban_res.status_code, 200)
        self.assertTrue(ban_res.get_json()['banned'])

        # Login attempt for banned player should be blocked
        login_res = self.client.post('/api/player/login', json={
            'username': uname,
            'password': 'Password123!'
        })
        self.assertEqual(login_res.status_code, 403)
        self.assertTrue(login_res.get_json()['banned'])

        # Re-authenticate as admin
        self.client.post('/api/admin/login', json={'username': config.ADMIN_USERNAME, 'password': config.ADMIN_PASSWORD})

        # Admin unbans player
        unban_res = self.client.post('/api/admin/players/ban', json={
            'query': uname,
            'action': 'unban'
        })
        self.assertEqual(unban_res.status_code, 200)
        self.assertFalse(unban_res.get_json()['banned'])

        # Login succeeds after unban
        login_ok = self.client.post('/api/player/login', json={
            'username': uname,
            'password': 'Password123!'
        })
        self.assertEqual(login_ok.status_code, 200)

    def test_admin_can_delete_player_and_deputy_cannot(self):
        import secrets
        uname = 'UserToDel_' + secrets.token_hex(3)
        uemail = uname.lower() + '@example.com'
        reg = self.client.post('/api/player/register', json={
            'username': uname,
            'email': uemail,
            'password': 'Password123!',
        })
        self.assertEqual(reg.status_code, 200)

        # Login as Admin
        self.client.post('/api/admin/login', json={'username': config.ADMIN_USERNAME, 'password': config.ADMIN_PASSWORD})
        plist = self.client.get('/api/admin/players').get_json()['players']
        p_obj = next(p for p in plist if p['username'] == uname)
        pid = p_obj['id']

        # Admin can view plain password
        self.assertEqual(p_obj['password'], 'Password123!')

        # Make another user Deputy Admin
        deputy_name = 'Deputy_' + secrets.token_hex(3)
        self.client.post('/api/player/register', json={
            'username': deputy_name,
            'email': deputy_name.lower() + '@example.com',
            'password': 'DeputyPassword123!',
        })
        self.client.post('/api/admin/login', json={'username': config.ADMIN_USERNAME, 'password': config.ADMIN_PASSWORD})
        deputy_id = next(p for p in self.client.get('/api/admin/players').get_json()['players'] if p['username'] == deputy_name)['id']
        self.client.post(f'/api/admin/players/{deputy_id}/role', json={'role': 'Deputy Admin'})

        # Login as Deputy Admin
        self.client.post('/api/player/login', json={'username': deputy_name, 'password': 'DeputyPassword123!'})

        # Deputy Admin sees masked password
        deputy_view = self.client.get('/api/admin/players').get_json()['players']
        p_deputy_seen = next(p for p in deputy_view if p['username'] == uname)
        self.assertEqual(p_deputy_seen['password'], '••••••••')

        # Deputy Admin CANNOT delete account
        del_fail = self.client.delete(f'/api/admin/players/{pid}')
        self.assertEqual(del_fail.status_code, 403)

        # Re-login as full Admin
        self.client.post('/api/admin/login', json={'username': config.ADMIN_USERNAME, 'password': config.ADMIN_PASSWORD})

        # Full Admin CAN delete account
        del_ok = self.client.delete(f'/api/admin/players/{pid}')
        self.assertEqual(del_ok.status_code, 200)

        # Verify player is gone
        plist_after = self.client.get('/api/admin/players').get_json()['players']
        self.assertFalse(any(p['id'] == pid for p in plist_after))

    def test_security_headers_present(self):
        resp = self.client.get('/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(resp.headers.get('X-Frame-Options'), 'SAMEORIGIN')
        self.assertEqual(resp.headers.get('X-XSS-Protection'), '1; mode=block')

    def test_health_check_endpoints(self):
        for path in ('/healthz', '/health', '/ping'):
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.get_json()['status'], 'ok')

    def test_anti_ddos_rate_limiting(self):
        from euphoria.security import rate_limiter
        test_ip = '198.51.100.99'
        # Emulate repeated calls
        for _ in range(20):
            limited, _ = rate_limiter.is_rate_limited(test_ip, is_auth=True)
            self.assertFalse(limited)
        # 21st call should trigger rate limiter
        limited, retry_after = rate_limiter.is_rate_limited(test_ip, is_auth=True)
        self.assertTrue(limited)
        self.assertGreater(retry_after, 0)

    def test_registration_email_validation(self):
        # Invalid email should fail with 400
        bad_resp = self.client.post('/api/player/register', json={
            'username': f'bad_email_{secrets.token_hex(4)}',
            'email': 'not-an-email',
            'password': 'Password123!'
        })
        self.assertEqual(bad_resp.status_code, 400)
        self.assertIn('корректный адрес', bad_resp.get_json()['message'])

        # Valid email should succeed
        ok_resp = self.client.post('/api/player/register', json={
            'username': f'good_email_{secrets.token_hex(4)}',
            'email': f'good_{secrets.token_hex(4)}@example.com',
            'password': 'Password123!'
        })
        self.assertEqual(ok_resp.status_code, 200)

    def test_forgot_and_reset_password_flow(self):
        # 1. Register a test player
        uname = f'pw_user_{secrets.token_hex(4)}'
        email = f'reset_{secrets.token_hex(4)}@domain.org'
        orig_pw = 'OldPassword123!'
        self.client.post('/api/player/register', json={
            'username': uname,
            'email': email,
            'password': orig_pw
        })

        # 2. Request forgot password code
        f_resp = self.client.post('/api/player/forgot-password', json={
            'login_or_email': uname
        })
        self.assertEqual(f_resp.status_code, 200)
        data = f_resp.get_json()
        self.assertTrue(data['ok'])
        
        from euphoria.db import get_db
        c = get_db()
        row = c.execute('SELECT code FROM password_resets WHERE email=? ORDER BY id DESC LIMIT 1', (email,)).fetchone()
        code = row['code']
        c.close()
        self.assertEqual(len(code), 6)

        # 3. Try with invalid code
        bad_reset = self.client.post('/api/player/reset-password', json={
            'login_or_email': uname,
            'code': '000000',
            'new_password': 'NewPassword999!'
        })
        self.assertEqual(bad_reset.status_code, 400)

        # 4. Reset with valid code
        new_pw = 'NewPassword999!'
        good_reset = self.client.post('/api/player/reset-password', json={
            'login_or_email': uname,
            'code': code,
            'new_password': new_pw
        })
        self.assertEqual(good_reset.status_code, 200)
        self.assertTrue(good_reset.get_json()['ok'])

        # 5. Verify login works with new password
        login_resp = self.client.post('/api/player/login', json={
            'username': uname,
            'password': new_pw
        })
        self.assertEqual(login_resp.status_code, 200)

    def test_admin_can_inspect_password_reset_codes(self):
        # 1. Register and request code
        uname = f'user_res_{secrets.token_hex(4)}'
        email = f'{uname}@example.com'
        self.client.post('/api/player/register', json={
            'username': uname,
            'email': email,
            'password': 'Password123!'
        })
        self.client.post('/api/player/forgot-password', json={'login_or_email': uname})

        # 2. Login as admin
        self.client.post('/api/admin/login', json={'username': config.ADMIN_USERNAME, 'password': config.ADMIN_PASSWORD})

        # 3. Fetch resets log
        r = self.client.get('/api/admin/password-resets')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['ok'])
        found = any(x['username'] == uname for x in data['resets'])
        self.assertTrue(found)

    def test_player_ip_tracking_and_admin_ip_ban(self):
        # 1. Register player with specific IP
        uname = f'ip_user_{secrets.token_hex(4)}'
        email = f'{uname}@ip-test.com'
        test_ip = '198.51.100.42'
        self.client.post('/api/player/register', json={
            'username': uname,
            'email': email,
            'password': 'Password123!'
        }, environ_base={'REMOTE_ADDR': test_ip})

        # 2. Login as admin and list players to verify IP is present
        self.client.post('/api/admin/login', json={'username': config.ADMIN_USERNAME, 'password': config.ADMIN_PASSWORD})
        resp = self.client.get('/api/admin/players')
        self.assertEqual(resp.status_code, 200)
        p_list = resp.get_json()['players']
        player = next(p for p in p_list if p['username'] == uname)
        self.assertEqual(player['reg_ip'], test_ip)
        self.assertEqual(player['last_ip'], test_ip)

        # 3. Ban player by IP
        ban_resp = self.client.post(f'/api/admin/players/{player["id"]}/ban-ip')
        self.assertEqual(ban_resp.status_code, 200)
        self.assertTrue(ban_resp.get_json()['ok'])

        # 4. Verify player IP is banned in ip_bans table
        from euphoria.db import get_db
        c = get_db()
        ban_row = c.execute('SELECT * FROM ip_bans WHERE ip=? AND active=1', (test_ip,)).fetchone()
        self.assertIsNotNone(ban_row)
        c.close()

    def test_sbp_settings_and_order_flow(self):
        # 1. Test public settings
        r = self.client.get('/api/payment/settings')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()['ok'])

        # 2. Login admin and update settings
        self.client.post('/api/admin/login', json={'username': config.ADMIN_USERNAME, 'password': config.ADMIN_PASSWORD})
        save_r = self.client.post('/api/admin/payment/settings', json={
            'sbp_phone': '+7 (999) 777-88-99',
            'sbp_bank': 'Т-Банк',
            'sbp_recipient': 'Алексей А.',
            'merchant_enabled': True,
            'merchant_provider': 'aaio',
            'merchant_shop_id': 'shop_123',
            'merchant_secret': 'sec_456'
        })
        self.assertEqual(save_r.status_code, 200)
        self.assertTrue(save_r.get_json()['ok'])

        # 3. Create SBP order
        ord_r = self.client.post('/api/payment/create-sbp-order', json={
            'product': '365 Days'
        })
        self.assertEqual(ord_r.status_code, 200)
        ord_data = ord_r.get_json()
        self.assertTrue(ord_data['ok'])
        self.assertEqual(ord_data['phone'], '+7 (999) 777-88-99')
        self.assertTrue(ord_data['order_id'].startswith('EUPH-'))

        # 4. Trigger Webhook with order_id
        wh_r = self.client.post('/api/payment/webhook', json={
            'order_id': ord_data['order_id'],
            'status': 'success'
        })
        self.assertEqual(wh_r.status_code, 200)


if __name__ == '__main__':
    unittest.main()
