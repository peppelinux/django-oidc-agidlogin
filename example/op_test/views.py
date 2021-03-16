import json
import logging
import urllib


from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jwk.rsa import RSAKey
from django.http import JsonResponse, HttpResponseRedirect
from django.views.decorators.csrf import csrf_exempt
from django.urls import reverse
from oidcmsg.message import Message


logger = logging.getLogger(__name__)

ISSUER = "http://localhost:8888"
PROVIDER_CONFIG = {
    "issuer": ISSUER,
    "introspection_endpoint": f"{ISSUER}/token/introspection", # todo
    "revocation_endpoint": f"{ISSUER}/token/revocation", # todo
    "end_session_endpoint": f"{ISSUER}/session/end", # todo

    "jwks_uri": f"{ISSUER}/oidc/op/jwks",
    "authorization_endpoint": f"{ISSUER}/oidc/op/authz",
    "token_endpoint": f"{ISSUER}/oidc/op/token",
    "userinfo_endpoint": f"{ISSUER}/oidc/op/userinfo",

    "claims_parameter_supported": True,
    "claims_supported": [ "sub", "provider", "provider_id", "firstname", "lastname", "fiscalNumber", "email", "email_id", "phone", "placeOfBirth", "dateOfBirth", "gender", "address", "last_access", "user_policy", "entity", "sid", "auth_time", "iss" ],
    "grant_types_supported": [ "authorization_code", "client_credentials"],
    "id_token_signing_alg_values_supported": [ "RS256"],
    "request_object_signing_alg_values_supported": ["RS256", "PS256", "ES256"],
    "request_parameter_supported": True,
    "request_uri_parameter_supported": True,
    "response_modes_supported": [ "form_post", "fragment", "query", "jwt", "query.jwt", "fragment.jwt", "form_post.jwt" ],
    "response_types_supported": ["code"],
    "scopes_supported": ["openid", "profile" ],
    "subject_types_supported": ["public"],
    "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
    "userinfo_signing_alg_values_supported": ["HS256", "RS256"],
    "code_challenge_methods_supported": [ "S256" ],
    "authorization_signing_alg_values_supported": [ "HS256", "RS256" ],
    "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
    "introspection_endpoint_signing_alg_values_supported": ["HS256", "RS256"],
    "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
    "id_token_encryption_alg_values_supported": ["A128KW","A256KW","ECDH-ES","ECDH-ES+A128KW","ECDH-ES+A256KW","RSA-OAEP"],
    "id_token_encryption_enc_values_supported": ["A128CBC-HS256","A128GCM","A256CBC-HS512","A256GCM"],
    "userinfo_encryption_alg_values_supported": ["A128KW","A256KW","ECDH-ES","ECDH-ES+A128KW","ECDH-ES+A256KW","RSA-OAEP"],
    "userinfo_encryption_enc_values_supported": ["A128CBC-HS256","A128GCM","A256CBC-HS512","A256GCM"],
    "introspection_encryption_alg_values_supported": ["A128KW","A256KW","ECDH-ES","ECDH-ES+A128KW","ECDH-ES+A256KW","RSA-OAEP"],
    "introspection_encryption_enc_values_supported": ["A128CBC-HS256","A128GCM","A256CBC-HS512","A256GCM"],
    "authorization_encryption_alg_values_supported": ["A128KW","A256KW","ECDH-ES","ECDH-ES+A128KW","ECDH-ES+A256KW","RSA-OAEP"],
    "authorization_encryption_enc_values_supported": ["A128CBC-HS256","A128GCM","A256CBC-HS512","A256GCM"],
    "request_object_encryption_alg_values_supported": ["A128KW","A256KW"],
    "request_object_encryption_enc_values_supported": ["A128CBC-HS256","A128GCM","A256CBC-HS512","A256GCM"],
    "claim_types_supported": ["normal"]
}

STATE = {}


def create_jwks():
    from cryptojwt.jwk.rsa import new_rsa_key
    rsa_key = new_rsa_key()

    jwk_priv = rsa_key.serialize(private=True)
    # public
    jwk_pub = rsa_key.serialize()
    return jwk_priv, jwk_pub


JWK_PRIVATE, JWK_PUBLIC = create_jwks()


def provider_discovery_request(request):
    return JsonResponse(PROVIDER_CONFIG)


def jwks_request(request):
    return JsonResponse({'keys': [JWK_PUBLIC,]})


def authz_request(request):
    STATE = {k:v for k,v in request.GET.items()}
    values = {'code': 238947239847293839247239847239,
              'state': STATE.get('state')}
    url = f"{STATE['redirect_uri']}?{urllib.parse.urlencode(values)}"
    return HttpResponseRedirect(url)


@csrf_exempt
def token_request(request):
    logger.debug(f'{request.headers}: {request.POST}')

    id_token = {
                    "sub": "Microsoft:test-protocollo-2@agid.gov.it",
                    "nonce": "ITyym7MixGzWnTp4AMFimVk5",
                    "at_hash": "a_jseUswllpYcJVPYEcj5w",
                    "sid": "3dd91e80-ec4b-4cca-af44-58dfdd0544cb",
                    "aud": "2c43a070-425f-4613-859c-d234ec7d71af",
                    "exp": 1615749924,
                    "iat": 1615746324,
                    "iss": ISSUER
                }
    jwt_id_token = Message(**id_token)
    keys = [RSAKey(**JWK_PRIVATE)]
    signed_jwt_id_token = jwt_id_token.to_jwt(keys, "RS256")

    return JsonResponse(
        {
            'access_token': 'sadasd',
            'id_token': signed_jwt_id_token,
            'token_type': 'bearer',
            'expires_in': 3600,
            'scope': 'openid profile'
        }
    )


def userinfo_request(request):
    logger.debug(f'{request.headers}: {request.POST}')
    return JsonResponse(
        {
            'sub': 'that-subject',
            'firstname': 'sando',
            'lastname': 'kan',
            'email': 'sando@k.an'
        }
    )

