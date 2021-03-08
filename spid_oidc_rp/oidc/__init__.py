import json
import logging
import requests

from cryptojwt.jwk.jwk import key_from_jwk_dict


logger = logging.getLogger(__name__)


class OidcProviderDiscovery(object):
    """
        https://openid.net/specs/openid-connect-core-1_0.html#SelfIssued
    """
    def provider_discovery(self, client_conf):
        """
            Minimal Provider Discovery endpoint request processing
        """
        oidc_op_wk_url = f"{client_conf['issuer']}/.well-known/openid-configuration"
        oidc_op_wk = requests.get(
            client_conf.get('discovery_url') or oidc_op_wk_url,
            verify=client_conf['httpc_params']['verify']
        )
        return oidc_op_wk.json()

    def get_jwks_from_jwks_uri(self, jwks_uri, verify=True)->tuple:
        """
            builds jwks objects, importable in a Key Jar
        """
        jwks_dict = requests.get(jwks_uri, verify=verify).json()
        return jwks_dict, [key_from_jwk_dict(i) for i in jwks_dict["keys"]]


class OidcUserInfo(object):
    """
        https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
    """
    def get_userinfo(self, state, access_token, provider_conf, verify):
        """
            User Info endpoint request with bearer access token
        """
        # userinfo
        headers = {'Authorization': f'Bearer {access_token}'}
        authz_userinfo = requests.get(provider_conf['userinfo_endpoint'],
                                      headers=headers, verify=verify)
        if authz_userinfo.status_code != 200:
            logger.error(
                f'Something went wrong with {state}: {authz_userinfo.content}')
            return HttpResponseBadRequest(
                _('An error occourred while getting user attributes')
            )
        else:
            try:
                authz_userinfo = json.loads(authz_userinfo.content.decode())
                logger.debug(f"Userinfo endpoint result: {authz_userinfo}")
                return authz_userinfo
            except Exception as e:
                logger.error(f'Something went wrong with {state}: {e}')
                return False
