import base64
import json
import hashlib
import logging
import os
import random
import re
import string
import urllib


from cryptojwt import KeyJar
from cryptojwt.key_jar import init_key_jar, KeyJar
from django.conf import settings
from oidcrp import RPHandler
from oidcrp.util import load_yaml_config, load_configuration
from oidcmsg.message import Message


logger = logging.getLogger(__name__)


def init_oidc_rp_handler(app):
    _rp_conf = app.config

    if _rp_conf.get('rp_keys'):
        _kj = init_key_jar(**_rp_conf['rp_keys'])
        _path = _rp_conf['rp_keys']['public_path']
        # removes ./ and / from the begin of the string
        _path = re.sub('^(.)/', '', _path)
    else:
        _kj = KeyJar()
        _path = ''
    _kj.httpc_params = _rp_conf['httpc_params']
    hash_seed = app.config.get('hash_seed', "BabyHoldOn")
    rph = RPHandler(
                        _rp_conf['base_url'],
                        _rp_conf['clients'],
                        services=_rp_conf['services'],
                        hash_seed=hash_seed,
                        keyjar=_kj,
                        jwks_path=_path,
                        httpc_params=_rp_conf['httpc_params'],
                        # state_db = STATE_DB
                    )

    return rph


def get_rph(config_fname=None):
    # config = load_yaml_config(config_file)
    config = config_fname or settings.JWTCONN_RP_CONF
    app = type('RPApplication', (object,), {"config": config})
    rph = init_oidc_rp_handler(app)
    return rph


def fancy_print(msg, dict_obj):
    print('\n\n{}\n'.format(msg),
          json.dumps(dict_obj, indent=2) if dict_obj else '')


def http_redirect_uri_to_dict(url):
    splitted = urllib.parse.splitquery(url)
    data = dict(urllib.parse.parse_qsl(splitted[1]))
    data.update({'endpoint': splitted[0]})
    return data


def http_dict_to_redirect_uri_path(data):
    return urllib.parse.urlencode(data)


def fancy_print(msg, dict_obj):
    print('{}'.format(msg), json.dumps(dict_obj, indent=2) if dict_obj else '')


def decode_token(bearer_token, keyjar, verify_sign=True):
    msg = Message().from_jwt(bearer_token,
                             keyjar=keyjar,
                             verify=verify_sign)
    return msg.to_dict()


def random_string(n=27):
    return ''.join(
        random.choices(string.ascii_letters + string.digits, k=n)
    )


def get_pkce(method='S256'):
    hashers = {
        'S256' : hashlib.sha256
    }

    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
    code_verifier = re.sub('[^a-zA-Z0-9]+', '', code_verifier)

    code_challenge = hashers.get(method)(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
    code_challenge = code_challenge.replace('=', '')

    return {
        'code_verifier': code_verifier,
        'code_challenge': code_challenge,
        'code_challenge_method': method
    }


def get_issuer_keyjar(jwks, issuer:str):
    key_jar = KeyJar()
    # "" means default, you can always point to a issuer identifier
    key_jar.import_jwks(jwks, issuer_id=issuer)
    return key_jar


def validate_jwt(jwt:str, key_jar):
    try:
        recv = Message().from_jwt(jwt, keyjar=key_jar)
        return recv.verify(), key_jar
    except:
        return False
