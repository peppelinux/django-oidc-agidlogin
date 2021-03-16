from django.test import TestCase, Client, RequestFactory
from django.urls import reverse


class OidcRpTest(TestCase):

    def test_session(self):
        url = f'{reverse("spid_oidc_rp:spid_oidc_rp_begin")}?issuer_id=op_test'
        req = Client()
        res = req.get(url)
        self.assertTrue(res.status_code == 302)

        authz_url = f'{reverse("op_test:spid_oidc_op_authz")}?{res.url.split("?")[1]}'
        res = req.get(authz_url)
        self.assertTrue(res.status_code == 302)
        self.assertIn('code=', res.url)

        url = f'{reverse("spid_oidc_rp:spid_oidc_rp_callback")}?{res.url.split("?")[1]}'
        res = req.get(url)
        self.assertTrue(res.status_code == 302)

        url = f'{reverse("spid_oidc_rp:spid_oidc_rp_echo_attributes")}'
        res = req.get(url)
        self.assertIn('sando', res.content.decode())
