# spid-django-oidc
OIDC Relying Party (RP) or OAuth2 Client based on django and [jwtconnect.io](https://jwtconnect.io/),
specifically built from scratch starting from [oidcmsg](https://oidcmsg.readthedocs.io/en/latest/)
and [cryptojwt](https://cryptojwt.readthedocs.io/en/latest/).

## Why

spid-django-oidc enables OIDC Authentication in your django app.

To date there are many libraries that enable OAuth2 and OIDC in a Django project,
however spid-django-oidc wants to offer itself as a simple alternative, compliant with
standards and in line with what [OIDC SPID](https://docs.italia.it/AgID/documenti-in-consultazione/lg-openidconnect-spid-docs/it/bozza/index.html)
guidelines defines.

What is available today represents the bare essentials to manage an authorization flow and requests
for token acquisition and user information, processing of attributes and identity reunification functions.

In the event that some other functionality is required, this one relating to specific RFCs and draft of these, it will be possible to integrate them.

## Features

Regarding Oauth2

 - OAuth2/OIDC Authorization Code Grant: [rfc6749](https://tools.ietf.org/html/rfc6749#section-4.1) and [openid-connect-core-1_0](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)
 - PKCE: [rfc7636](https://tools.ietf.org/html/rfc7636)

Regarding OIDC

 - Discovery Provider: [openid-connect-core-1_0](https://openid.net/specs/openid-connect-core-1_0.html#SelfIssuedDiscovery)
 - UserInfo endpoint: [UserInfo](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)

Regarding django user management

 - user attributes processing and rewriting from OAuth2 claims
 - reunification of digital identities


## Example project

````
git clone https://github.com/peppelinux/spid-django-oidc.git
cd spid-django-oidc
pip install virtualenv
virtualenv -ppython3 env
source env/bin/activate
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

Then start the demo server
````
pip install -r requirements.txt
cd example
./manage.py migrate
./manage.py createsuperuser
./manage.py runserver
````

## Installation


````
pip install spid-django-oidc
````

then adapt your project setting file as shown in `example/` project.
import `spid_oidc_rp.urls` in your project `urls.py` file.
A Documentation with all the parameters will come soon!


## Authors

 - Giuseppe De Marco


## Special thanks to

 - Mirko Cappuccia, for having motivated the birth of this project
 - Michele D'Amico, for the support and willingness to welcome opinions, ideas and contributions
 - Francesco Filicetti, for the excellent [uniTicket](https://github.com/UniversitaDellaCalabria/uniTicket) which is the platform thanks to which all this began
 - Roland Hedberg, for being the author of jwtconnect.io, for being open, available and intellectually active towards the community and any developer who approaches
