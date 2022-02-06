# django-oidc-agidlogin

![CI build](https://github.com/peppelinux/spid-django-oidc/workflows/spid-django-oidc/badge.svg)
![Python version](https://img.shields.io/badge/license-Apache%202-blue.svg)
[![codecov](https://codecov.io/gh/peppelinux/spid-django-oidc/branch/main/graph/badge.svg)](https://codecov.io/gh/peppelinux/spid-django-oidc)
![License](https://img.shields.io/badge/python-3.7%20%7C%203.8%20%7C%203.9-blue.svg)

OpenID Connect 1.0 is a simple identity layer on top of the OAuth 2.0 protocol.
It enables Clients to verify the identity of the End-User based on the authentication
performed by an Authorization Server, as well as to obtain basic profile information
about the End-User in an interoperable and REST-like manner.


This project is a OIDC Relying Party (RP) or OAuth2 Client based on django and [jwtconnect.io](https://jwtconnect.io/),
specifically built from scratch with [oidcmsg](https://oidcmsg.readthedocs.io/en/latest/)
and [cryptojwt](https://cryptojwt.readthedocs.io/en/latest/).


## Introduction

django-oidc-agidlogin enables OIDC Authentication in your django project.

To date there are many libraries that enable OAuth2 and OIDC in a Django project,
this project instead born to be lightweight and simple.

What is available today represents the bare essentials to manage an authorization flow and requests
for token acquisition and user information, processing of attributes and identity reunification functions.


## Features

Regarding OAuth2

 - Authorization Code Grant: [rfc6749](https://tools.ietf.org/html/rfc6749#section-4.1)
 - PKCE: [rfc7636](https://tools.ietf.org/html/rfc7636)

Regarding OIDC

 - CodeFlowAuth: [openid-connect-core-1_0](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)
 - Discovery Provider: [openid-connect-core-1_0](https://openid.net/specs/openid-connect-core-1_0.html#SelfIssuedDiscovery)
 - UserInfo endpoint: [UserInfo](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
 - RP Initiated logout: [openid-connect-rpinitiated-1_0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)

Regarding django user management

 - user attributes processing and rewriting from OAuth2 claims
 - reunification of digital identities


## Installation

````
pip install spid_oidc_rp
````

then adapt your project setting file as shown in `example/` project.
import `spid_oidc_rp.urls` in your project `urls.py` file.


## Example project

````
git clone https://github.com/peppelinux/django-oidc-agidlogin.git
cd spid-django-oidc
pip install virtualenv
virtualenv -ppython3 env
source env/bin/activate
python setup.py install
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
./manage.py runserver 0.0.0.0:8888
````

Open your web browser and go to your debug server url, eg:

`http://localhost:8888/oidc/rp/begin?issuer_id=op_test`

where `issuer_id` is one of the configured in `JWTCONN_RP_CLIENTS`.


## Settings

Please see `example/example/spid_oidc_rp_settings.py` as example.

- `JWTCONN_RP_PREFS`: General informations, default parameters during authentication requests, like the `scope` attribute
- `JWTCONN_RP_CLIENTS`: All the Clients configured in.
    - `discovery_url`: only usefull if the OP/AS doesn't have a standard `.well-known` discovery path
    - `redirect_uris`: this must match with the `spid_oidc_rp_callback` url, defined in your project `urls.py`
    - `httpc_params`: python requests arguments, by default `verify` that checks if the provider have a valid https certificate
    - `add_ons.pkce`: enable PKCE (rfc7636)
    - `user_attributes_map`: defines how oidc claims should be mapped to User model. You can even use a function to do rewrite or create new attributes (feel free to contribute with new processors in `processors.py`)
        ````
        (
         {
            'func': 'spid_oidc_rp.processors.issuer_prefixed_sub',
            'kwargs': {'sep': '__'}
         },
        )
        ````
        Otherwise a simple mapping like this: `('firstname',),`
        Otherwise a multiple OR sequence: `('firstname', 'lastname'),`. This will check for the first occourrence

    - `user_lookup_field`: the django user field, where the reunification lookup happens, eg: `('username'),`
    - `user_create`: creates a new user if the reunification lookup fails
    - `login_redirect_url`: where the user will be redirected when finally authenticated
- `JWTCONN_PKCE_CONF`: function and general paramenters for PKCE creation


## Tests

Tests needs that a debug server have to be executed, this is for simulate the entire auth code flow as it's real.
spid-django-oidc have an application called `op_test` that's involved in testing.

So, first of all execute the test server as follow
````
./manage.py runserver 0.0.0.0:8888
````

Then run the tests in a separate shell with `./manage.py test`.

Code Coverage
````
pip install coverage
coverage erase; coverage run ./manage.py test ; coverage report -m
````

## Contribute

In the event that some other functionality is required, relating to specific RFCs and draft of these, please open an issue to integrate them as soon as possibile.

Your contribution is welcome, please open your Pull Requests on the dev branch.

## Authors

 - Giuseppe De Marco


## Special thanks to

 - Mirko Cappuccia, for having motivated the birth of this project
 - Michele D'Amico, for the support and willingness to welcome opinions, ideas and contributions
 - Francesco Filicetti, for the excellent [uniTicket](https://github.com/UniversitaDellaCalabria/uniTicket) which is the platform thanks to which all this began
 - Roland Hedberg, for being the author of jwtconnect.io, for being open, available and intellectually active towards the community and any developer who approaches
