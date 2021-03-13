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
                         HttpResponseRedirect,)
from django.views import View
from django.shortcuts import render
from django.utils.translation import gettext as _
from jwtconnect_oidc_rp.utils import get_rph

from . exceptions import MisconfiguredClientIssuer
from . models import OidcAuthenticationRequest
from . utils import (http_redirect_uri_to_dict,
                     decode_token,
                     random_string,
                     http_dict_to_redirect_uri_path,
                     get_pkce,
                     )


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
            # rph.issuer2rp[authz.issuer].service['authorization'].state_db
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
            scope = client_prefs['scope'][0],
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
            # rph.issuer2rp[authz.issuer].service['authorization'].state_db
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
