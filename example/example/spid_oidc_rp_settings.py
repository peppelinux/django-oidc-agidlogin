JWTCONN_RP_PREFS = {
    'application_name': 'that_fancy_rp',
    'application_type': 'web',
    'contacts': ['ops@example.com'],
    'response_types': ['code'],
    'scope': ['openid', 'profile', 'email'],
    'token_endpoint_auth_method': ['client_secret_basic',
                                   'client_secret_post']
}


JWTCONN_ATTR_MAP = {
    'username': {
                    'func': 'spid_oidc_rp.processors.issuer_prefixed_sub',
                    'kwargs': {'sep': '__'}
                },
    'first_name': ('firstname',),
    'last_name': ('lastname',),
    'email': ('email',),
}


JWTCONN_PKCE_CONF = {
    'function': 'spid_oidc_rp.utils.get_pkce',
    'kwargs': {
        'code_challenge_length': 64,
        'code_challenge_method': 'S256'
    }
}


JWTCONN_RP_CLIENTS = {
        'agid_login_local': {
            'issuer': 'https://login.agid.gov.it',
            'client_preferences': JWTCONN_RP_PREFS,
            'client_id': 'that-id',
            'client_secret': 'that-secret',
            'redirect_uris': ['http://localhost:8888/callback'],
            'httpc_params':  {'verify': True},
            'add_ons': {
                'pkce': JWTCONN_PKCE_CONF
            },
            'user_attributes_map': JWTCONN_ATTR_MAP,
            'user_lookup_field': ('username'),
            'user_create': True,
            'login_redirect_url': '/echo_attributes'
        }
}
