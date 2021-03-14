# spid-django-oidc
OIDC Relying Party (RP) or Oauth2 Client based on django and jwtconnect.io.

## Why

spid-django-oidc was created with the aim of enabling a Django app to
proxy OIDC to **SPID** _AgID Login_, at the same time duel to create an OIDC
application profile in line with the guidelines
[OIDC SPID](https://docs.italia.it/AgID/documenti-in-consultazione/lg-openidconnect-spid-docs/it/bozza/index.html).

## Features

 - Discovery Provider: [openid-connect-core-1_0](https://openid.net/specs/openid-connect-core-1_0.html#SelfIssuedDiscovery)
 - OAuth2/OIDC Authorization Code Grant: [rfc6749](https://tools.ietf.org/html/rfc6749#section-4.1) and [openid-connect-core-1_0](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)
 - UserInfo endpoint: [UserInfo](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
 - PKCE: [rfc7636](https://tools.ietf.org/html/rfc7636)

## Example project

````
git clone https://github.com/peppelinux/spid-django-oidc.git
cd spid-django-oidc
pip install virtualenv
virtualenv -ppython3 env
source env/bin/activate

pip install -r requirements.txt
cd example
./manage.py migrate
./manage.py createsuperuser
./manage.py runserver
````

Before run, create a file called `example/spid_oidc_rp_settings_private.py` with your client credentials and configurations, as follows:

````
from . spid_oidc_rp_settings import JWTCONN_RP_PREFS, JWTCONN_PKCE_CONF, JWTCONN_ATTR_MAP

JWTCONN_RP_CLIENTS = {
        'agid_login_local': {
            'issuer': 'https://login.agid.gov.it',
            'client_preferences': JWTCONN_RP_PREFS,
            'client_id': 'private-information',
            'client_secret': 'private-information',
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
````

## Install in you Django project


````
pip install spid-django-oidc
````

then adapt your project setting file as shown in `example/` project.
A Documentation with all the parameters will come soon!


## Authors
 - Giuseppe De Marco
