import json
import logging
import requests

from cryptojwt.exception import BadSyntax
from cryptojwt.jwk.jwk import key_from_jwk_dict

from django.conf import settings
from django.contrib.auth import login, get_user_model
from django.http import (HttpResponse,
                         HttpResponseBadRequest,
                         HttpResponseRedirect)
from django.views import View
from django.utils.module_loading import import_string
from django.utils.translation import gettext as _
from requests.auth import HTTPBasicAuth

from . exceptions import MisconfiguredClientIssuer
from . models import OidcAuthenticationRequest, OidcAuthenticationToken
from . utils import (decode_token,
                     http_dict_to_redirect_uri_path,
                     http_redirect_uri_to_dict,
                     get_issuer_keyjar,
                     random_string,
                     validate_jwt)


logger = logging.getLogger(__name__)


class AgidOidcRpBeginView(View):
    """ View which processes the actual Authz request and
        returns a Http Redirect
    """

    def get_oidc_rp_issuer(self, request):
        """
            Disambiguation page if many clients have been confgiured
            Work in progress
        """
        available_issuers = settings.JWTCONN_RP_CLIENTS
        available_issuers_len = len(available_issuers)

        # todo: validate it upoun a schema
        issuer_id = request.GET.get('issuer_id')

        if not issuer_id:
            if available_issuers_len > 1:
                # TODO - a provider selection page here!
                raise NotImplemented()

            elif available_issuers_len == 1:
                issuer_id = list(available_issuers.keys())[0]
            else:
                raise MisconfiguredClientIssuer('No available issuers found')
        return issuer_id, available_issuers[issuer_id]['issuer']

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

    def get(self, request, *args, **kwargs):
        """
        https://login.agid.gov.it/.well-known/openid-configuration
        http://localhost:8888/oidc/spid/begin?issuer_id=agid_login_local
        """
        issuer_id, issuer_fqdn = self.get_oidc_rp_issuer(request)
        client_conf = settings.JWTCONN_RP_CLIENTS[issuer_id]

        try:
            provider_conf = self.provider_discovery(client_conf)
            jwks_dict, jwks = self.get_jwks_from_jwks_uri(
                provider_conf['jwks_uri'],
                verify=client_conf['httpc_params']['verify']
            )
        except Exception as e:
            _msg = f'Failed to get jwks from {issuer_fqdn}'
            logger.error(f'{_msg}: {e}')
            return HttpResponseBadRequest(_(_msg))

        client_prefs = client_conf['client_preferences']
        authz_endpoint = provider_conf['authorization_endpoint']
        authz_data = dict(
            scope=' '.join(client_prefs['scope']),
            redirect_uri=client_conf['redirect_uris'][0],
            response_type=client_prefs['response_types'][0],
            nonce=random_string(24),
            state=random_string(32),
            client_id=client_conf['client_id'],
            endpoint=authz_endpoint
        )

        # TODO: generalized addons loader
        has_pkce = client_conf.get('add_ons', {}).get('pkce')
        if has_pkce:
            pkce_func = import_string(has_pkce['function'])
            pkce_values = pkce_func(**has_pkce['kwargs'])
            authz_data.update(pkce_values)

        # create request in db
        authz_entry = dict(
            client_id = client_conf['client_id'],
            state = authz_data['state'],
            endpoint = authz_endpoint,
            issuer = issuer_fqdn,
            issuer_id = issuer_id,
            json = json.dumps(authz_data),
            jwks = json.dumps(jwks_dict),
            provider_configuration = json.dumps(provider_conf)
        )
        OidcAuthenticationRequest.objects.create(**authz_entry)

        authz_data.pop('code_verifier')
        uri_path = http_dict_to_redirect_uri_path(authz_data)
        url = '?'.join((authz_endpoint, uri_path))
        data = http_redirect_uri_to_dict(url)
        logger.debug(f'Started Authz: {url}')
        logger.debug(f'data: {data}')
        return HttpResponseRedirect(url)


class AgidOidcRpCallbackView(View):
    """
        View which processes
        /redirect_uri?code=tYkP854StRqBVcW4Kg4sQfEN5Qz&state=R9EVqaazGsj3wg5JgxIgm8e8U4BMvf7W
    """

    def process_user_attributes(self,
                                userinfo:dict,
                                client_conf:dict,
                                authz:OidcAuthenticationRequest):
        user_map = client_conf['user_attributes_map']
        data = dict()
        for k,v in user_map.items():
            if type(v) in (list, tuple):
                for i in v:
                    if i in userinfo:
                        data[k] = userinfo[i]
                        break
            elif isinstance(v, dict):
                args = (
                    userinfo,
                    client_conf,
                    authz.__dict__,
                    v['kwargs']
                )
                data[k] = import_string(v['func'])(*args)
        return data

    def user_reunification(self, user_attrs: dict, client_conf:dict):
        user_model = get_user_model()
        field_name = client_conf['user_lookup_field']
        lookup = {field_name: user_attrs[field_name]}
        user = user_model.objects.filter(**lookup)
        if user:
            return user.first()
        elif client_conf.get('user_create'):
            user = user_model.objects.create(**user_attrs)
        return user

    def get_token_endpoint_auth_method(self,
                                       client_conf: dict,
                                       method: str = None):
        method = method or client_conf['client_preferences']['token_endpoint_auth_method'][0]

        if all((method == 'client_secret_basic',
                'client_secret' in client_conf)):
            auth = HTTPBasicAuth(
                client_conf['client_id'],
                client_conf['client_secret']
            )
            data = {'auth': auth}
        elif all((method == 'client_secret_basic',
                  'client_token' in client_conf)):
            data = dict(
                headers={
                    'Authorization': f'Bearer {client_conf["client_token"]}'
                }
            )
        return data

    def token_request(self,
                      authz:OidcAuthenticationRequest,
                      token_endpoint_url:str,
                      token_req_data:dict,
                      verify=True):
        token_request = requests.post(token_endpoint_url,
                                      **token_req_data,
                                      verify=verify)

        if token_request.status_code != 200:
            logger.error(
                f'Something went wrong with {authz}: {token_request.content}')
        else:
            try:
                token_request = json.loads(token_request.content.decode())
                return token_request
            except Exception as e:
                logger.error(f'Something went wrong with {authz}: {e}')

    def get_userinfo(self, authz, authz_token, provider_conf, verify):
        """
            User Info endpoint request with bearer access token
        """
        # userinfo
        headers = {'Authorization': f'Bearer {authz_token.access_token}'}
        authz_userinfo = requests.get(provider_conf['userinfo_endpoint'],
                                      headers=headers, verify=verify)
        if authz_userinfo.status_code != 200:
            logger.error(
                f'Something went wrong with {authz}: {authz_userinfo.content}')
            return HttpResponseBadRequest(
                _('An error occourred while getting user attributes')
            )
        else:
            try:
                authz_userinfo = json.loads(authz_userinfo.content.decode())
                logger.debug(f"Userinfo endpoint result: {authz_userinfo}")
                return authz_userinfo
            except Exception as e:
                logger.error(f'Something went wrong with {authz}: {e}')
                return False

    def validate_jwt(self, authz, jwt, keyjar):
        _msg = (f'Something went wrong with {authz} JWT validation: '
                'Token validation fails [jwt]')
        if validate_jwt(jwt, key_jar=keyjar):
            return True
        else:
            logger.error(_msg)
            return False

    def decode_jwt(self, name, authz, jwt, keyjar):
        try:
            decoded_jwt = decode_token(jwt, keyjar=keyjar)
            logger.debug(f"{name}: {decoded_jwt}")
            return decoded_jwt
        except BadSyntax:
            logger.warning(
                f"{name} from {authz.issuer} is not in JWT format: {jwt}"
            )
        except Exception as e:
            logger.error(f"Something went wrong decoding {name}: {e}")

    def get(self, request, *args, **kwargs):
        """
           docs here
        """
        request_args = {k: v for k, v in request.GET.items()}
        authz = OidcAuthenticationRequest.objects.filter(
            state=request_args.get('state'),
        )
        if not authz:
            return HttpResponseBadRequest(_('Unsolicited response'))
        else:
            authz = authz.last()

        authz_data = json.loads(authz.json)
        provider_conf = json.loads(authz.provider_configuration)

        code = request.GET.get('code')
        authz_token = OidcAuthenticationToken.objects.create(
            authz_request=authz,
            code=code
        )

        grant_data = dict(
            grant_type='authorization_code',
            redirect_uri=authz_data['redirect_uri'],
            client_id=authz.client_id,
            state=authz.state,
            code=code,
        )

        if authz_data.get('code_verifier'):
            grant_data.update({'code_verifier': authz_data['code_verifier']})

        issuer_id = authz.issuer_id
        client_conf = settings.JWTCONN_RP_CLIENTS[issuer_id]

        auth_data = self.get_token_endpoint_auth_method(client_conf)
        token_req_data = dict(
            data=grant_data,
        )
        token_req_data.update(auth_data)
        token_request = self.token_request(
                    authz,
                    provider_conf['token_endpoint'],
                    token_req_data,
                    verify=client_conf['httpc_params']['verify']
        )

        if not token_request:
            return HttpResponseBadRequest(
                _('Authentication token seems not to be valid.')
            )

        jwks = json.loads(authz.jwks)
        keyjar = get_issuer_keyjar(jwks, authz.issuer)

        if not self.validate_jwt(authz, token_request['access_token'], keyjar):
            pass
            # Actually AgID Login have a non-JWT access token!
            # return HttpResponseBadRequest(
            # _('Authentication response validation error.')
            # )
        if not self.validate_jwt(authz, token_request['id_token'], keyjar):
            return HttpResponseBadRequest(
                _('Authentication token validation error.')
            )

        # just for debugging purpose ...
        decoded_id_token = self.decode_jwt(
            'ID Token', authz, token_request['id_token'], keyjar
        )
        decoded_access_token = self.decode_jwt(
            'Access Token', authz, token_request['access_token'], keyjar
        )

        authz_token.access_token = token_request['access_token']
        authz_token.id_token = token_request['id_token']
        authz_token.scope = token_request['scope']
        authz_token.token_type = token_request['token_type']
        authz_token.expires_in = token_request['expires_in']
        authz_token.save()

        userinfo = self.get_userinfo(
            authz, authz_token, provider_conf,
            verify=client_conf['httpc_params']['verify'])
        if not userinfo:
            return HttpResponseBadRequest(
                _('UserInfo response seems not to be valid.')
            )

        # here django user attr mapping
        user_attrs = self.process_user_attributes(
                        userinfo, client_conf, authz
                    )
        user = self.user_reunification(user_attrs, client_conf)
        login(request, user)
        return HttpResponseRedirect(
            getattr(settings, 'LOGIN_REDIRECT_URL', '/')
        )
