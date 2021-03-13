import json
import logging
import requests

from cryptojwt.exception import BadSyntax
from cryptojwt.jwk.jwk import key_from_jwk_dict

from django.conf import settings
from django.core.exceptions import ValidationError
from django.http import (Http404,
                         HttpResponse,
                         HttpResponseBadRequest,
                         HttpResponseRedirect)
from django.views import View
from django.shortcuts import render
from django.utils.translation import gettext as _
from jwtconnect_oidc_rp.utils import get_rph
from requests.auth import HTTPBasicAuth

from . exceptions import MisconfiguredClientIssuer
from . models import OidcAuthenticationRequest, OidcAuthenticationToken
from . utils import (http_redirect_uri_to_dict,
                     decode_token,
                     random_string,
                     http_dict_to_redirect_uri_path,
                     get_pkce,
                     get_issuer_keyjar,
                     validate_jwt)


logger = logging.getLogger(__name__)
rph = get_rph()


class OidcRpBeginView(View):
    """ View which processes the actual Authz request and
        returns a Http Redirect
    """

    def get_oidc_rp_issuer(self, request):

        available_issuers = settings.JWTCONN_RP_CONF['clients']
        available_issuers_len = len(available_issuers)

        # todo: validate it upoun a schema
        issuer_id_value = request.GET.get('issuer_id')

        if available_issuers_len > 1:
            issuer_id = issuer_id_value
        elif available_issuers_len == 1:
            issuer_id = available_issuers.keys()[0]
        else:
            raise MisconfiguredClientIssuer('No available issuers found')
        return issuer_id, available_issuers[issuer_id]['issuer']


    def get(self, request, *args, **kwargs):
        """
        https://login.agid.gov.it/.well-known/openid-configuration
        http://localhost:8888/rp/begin?issuer_id=agid_login_local
        """

        issuer_id, issuer_fqdn = self.get_oidc_rp_issuer(request)
        info = rph.begin(issuer_id)

        url = info['url']
        data = http_redirect_uri_to_dict(url)
        authz = OidcAuthenticationRequest.objects.create(
                client_id = data['client_id'],
                state = data['state'],
                endpoint = data['endpoint'],
                json = json.dumps(data),
                issuer = issuer_fqdn,
                issuer_id = issuer_id,
                authz_url = url
        )
        # data = rph.issuer2rp[issuer_fqdn].service['authorization'].state_db.__dict__
        logger.debug(f'Started Authz: {url}')
        logger.debug(f'data: {data}')

        # for i in range(3):
            # logger.debug(f"rph.issuer2rp[authz.issuer].service['authorization'].state_db.set({data[list(data.keys())[i]]})")

        return HttpResponseRedirect(url)


class OidcRpCallbackView(View):
    """
        View which processes
        /redirect_uri?code=tYkP854StRqBVcW4Kg4sQfEN5Qz&state=R9EVqaazGsj3wg5JgxIgm8e8U4BMvf7W
    """

    def user_reunification(self, issuer_fqdn:str, userinfo:dict):
        pass


    def get(self, request, *args, **kwargs):
        """
           docs here
        """
        authz = OidcAuthenticationRequest.objects.filter(
                state = request.GET.get('state'),
        )
        if not authz:
            return HttpResponseBadRequest(_('Unsolicited response'))
        else:
            authz = authz.last()

        authz.code = request.GET.get('code')
        authz.save()

        request_args = {k:v for k,v in request.GET.items()}
        try:
            result = rph.finalize(authz.issuer, request_args)
        except KeyError as e:
            logger.error(f'{e}')
            return HttpResponseBadRequest(
                _('Your request is stale, please renew your authentication')
            )

        try:
            # issuer_fqdn = rph.hash2issuer['agid_login_local']
            issuer_keyjar = rph.issuer2rp[authz.issuer]
        except Exception as e:
            logger.error(
                f'Failed to access to {authz.issuer} (issuer) keyjar: {e}'
            )
            return HttpResponseBadRequest(
                _(f'Failed to access to {authz.issuer} (issuer) keyjar')
            )

        try:
            decoded_access_token = decode_token(result['token'],
                                                keyjar=issuer_keyjar.service_context.keyjar)
            logger.debug(f"Access Token: {decoded_access_token}")
        except BadSyntax as e:
            logger.warning(
                f"Access Token from {authz.issuer} is not in JWT format: {result['token']}"
            )
        except Exception as e:
            logger.error(f"Something went wrong decoding access_token: {e}" )

        logger.debug(f"ID Token: {result['id_token'].to_dict()}")
        # userinfo
        userinfo = result['userinfo']
        logger.debug(f"Userinfo endpoint result: {userinfo.to_dict()}")

        # here how to authenticate a user with a django attr mapping
        self.user_reunification(authz.issuer, userinfo)

        return HttpResponse('OK')



class AgidOidcRpBeginView(View):
    """ View which processes the actual Authz request and
        returns a Http Redirect
    """

    def get_oidc_rp_issuer(self, request):

        available_issuers = settings.JWTCONN_RP_CONF['clients']
        available_issuers_len = len(available_issuers)

        # todo: validate it upoun a schema
        issuer_id_value = request.GET.get('issuer_id')

        if available_issuers_len > 1:
            issuer_id = issuer_id_value
        elif available_issuers_len == 1:
            issuer_id = available_issuers.keys()[0]
        else:
            raise MisconfiguredClientIssuer('No available issuers found')
        return issuer_id, available_issuers[issuer_id]['issuer']


    def provider_discovery(self, client_conf):
        oidc_op_wk_url = f"{client_conf['issuer']}/.well-known/openid-configuration"
        oidc_op_wk = requests.get(
             client_conf.get('discovery_url') or oidc_op_wk_url
        )
        return oidc_op_wk.json()


    def get_jwks_from_jwks_uri(self, jwks_uri):
        jwks_dict = requests.get(jwks_uri).json()
        return jwks_dict, [key_from_jwk_dict(i) for i in jwks_dict["keys"]]


    def get(self, request, *args, **kwargs):
        """
        https://login.agid.gov.it/.well-known/openid-configuration
        http://localhost:8888/rp/begin?issuer_id=agid_login_local
        """
        issuer_id, issuer_fqdn = self.get_oidc_rp_issuer(request)
        client_conf = settings.JWTCONN_RP_CLIENTS[issuer_id]

        try:
            provider_conf = self.provider_discovery(client_conf)
            jwks_dict, jwks = self.get_jwks_from_jwks_uri(provider_conf['jwks_uri'])
        except Exception as e:
            _msg = f'Failed to get jwks from {issuer_fqdn}'
            logger.error(f'{_msg}: {e}')
            return HttpResponseBadRequest(_(_msg))

        client_prefs = client_conf['client_preferences']
        authz_endpoint = provider_conf['authorization_endpoint']
        authz_data = dict(
            scope = ' '.join(client_prefs['scope']),
            redirect_uri = client_conf['redirect_uris'][0], # todo: this would be shuffled ...
            response_type = client_prefs['response_types'][0], # todo: this would be dynamic by params
            nonce = random_string(24),
            state = random_string(32),
            client_id = client_conf['client_id'],
            endpoint = authz_endpoint
        )

        pkce_values = get_pkce()
        authz_data.update(pkce_values)

        uri_path = http_dict_to_redirect_uri_path(authz_data)
        url = '?'.join((authz_endpoint, uri_path))

        authz_data.pop('code_verifier')
        # create request in db
        authz_entry = dict(
            client_id = client_conf['client_id'],
            state = authz_data['state'],
            endpoint = authz_endpoint,
            authz_url = url,
            issuer = issuer_fqdn,
            issuer_id = issuer_id,
            json = json.dumps(authz_data),
            jwks = json.dumps(jwks_dict),
            provider_configuration = json.dumps(provider_conf)
        )
        authz_entry.update(pkce_values)
        authz = OidcAuthenticationRequest.objects.create(**authz_entry)

        data = http_redirect_uri_to_dict(url)
        logger.debug(f'Started Authz: {url}')
        logger.debug(f'data: {data}')

        return HttpResponseRedirect(url)


class AgidOidcRpCallbackView(View):
    """
        View which processes
        /redirect_uri?code=tYkP854StRqBVcW4Kg4sQfEN5Qz&state=R9EVqaazGsj3wg5JgxIgm8e8U4BMvf7W
    """

    def user_reunification(self, issuer_fqdn:str, userinfo:dict):
        pass


    def get_userinfo(self, authz, authz_token, provider_conf):
        # userinfo
        headers = {'Authorization': f'Bearer {authz_token.access_token}'}
        authz_userinfo = requests.get(provider_conf['userinfo_endpoint'],
                                      headers = headers)
        if authz_userinfo.status_code != 200:
            logger.error(f'Something went wrong with {authz}: {authz_userinfo.content}')
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
        if validate_jwt(jwt, key_jar = keyjar):
            return True
        else:
            logger.error(_msg)
            return False


    def decode_jwt(self, name, authz, jwt, keyjar):
        try:
            decoded_jwt = decode_token(jwt, keyjar=keyjar)
            logger.debug(f"{name}: {decoded_jwt}")
            return decoded_jwt
        except BadSyntax as e:
            logger.warning(
                f"{name} from {authz.issuer} is not in JWT format: {jwt}"
            )
        except Exception as e:
            logger.error(f"Something went wrong decoding {name}: {e}" )


    def get(self, request, *args, **kwargs):
        """
           docs here
        """
        request_args = {k:v for k,v in request.GET.items()}
        authz = OidcAuthenticationRequest.objects.filter(
                state = request_args.get('state'),
        )
        if not authz:
            return HttpResponseBadRequest(_('Unsolicited response'))
        else:
            authz = authz.last()

        authz_data = json.loads(authz.json)
        provider_conf = json.loads(authz.provider_configuration)
        pkces = json.loads(authz.json)

        code = request.GET.get('code')
        grant_data = dict(
            grant_type = 'authorization_code',
            redirect_uri = authz_data['redirect_uri'],
            client_id = authz.client_id,
            state = authz.state,
            code = code,
            code_verifier = authz.code_verifier
        )

        authz_token = OidcAuthenticationToken.objects.create(
            authz_request = authz,
            code = code
        )

        issuer_id = authz.issuer_id
        client_conf = settings.JWTCONN_RP_CLIENTS[issuer_id]
        auth = HTTPBasicAuth(
                client_conf['client_id'],
                client_conf['client_secret']
            )
        token_request = requests.post(
                            provider_conf['token_endpoint'],
                            data=grant_data,
                            auth=auth
                        )

        if token_request.status_code != 200:
            logger.error(f'Something went wrong with {authz}: {token_request.content}')
            return HttpResponseBadRequest(
                _('Code Authentication failed, please renew your session')
            )
        else:
            try:
                token_request = json.loads(token_request.content.decode())
            except Exception as e:
                logger.error(f'Something went wrong with {authz}: {e}')
                return HttpResponseBadRequest(
                    _('Authentication response seems not to be valid.')
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
                _('Authentication response validation error.')
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

        userinfo = self.get_userinfo(authz, authz_token, provider_conf)
        if not userinfo:
            return HttpResponseBadRequest(
                _('UserInfo response seems not to be valid.')
            )

        # here django user attr mapping
        self.user_reunification(authz.issuer, userinfo)

        return HttpResponse('OK')
