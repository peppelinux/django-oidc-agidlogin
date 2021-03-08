import json
import logging
import re


from cryptojwt import KeyJar
from cryptojwt.key_jar import init_key_jar
from django.conf import settings
from oidcrp import RPHandler
from oidcrp.util import load_yaml_config, load_configuration


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
    rph = RPHandler(_rp_conf['base_url'], _rp_conf['clients'], services=_rp_conf['services'],
                    hash_seed=hash_seed, keyjar=_kj, jwks_path=_path,
                    httpc_params=_rp_conf['httpc_params']) #, verify_ssl=False)

    return rph


def get_rph(config_fname=None):
    # config = load_yaml_config(config_file)
    config = config_fname or settings.JWTCONN_OIDC_RP
    app = type('RPApplication', (object,), {"config": config})
    rph = init_oidc_rp_handler(app)
    return rph


def fancy_print(msg, dict_obj):
    print('\n\n{}\n'.format(msg),
          json.dumps(dict_obj, indent=2) if dict_obj else '')
