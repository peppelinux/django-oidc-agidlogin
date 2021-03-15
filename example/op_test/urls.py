from django.urls import path

from . views import *

app_name = "op_test"
urlpatterns = []

urlpatterns += path('oidc/op/openid-configuration', # '.well-known/openid-configuration',
                    provider_discovery_request,
                    name='spid_oidc_op_authz'),
urlpatterns += path('oidc/op/jwks',
                    jwks_request,
                    name='spid_oidc_op_jwks'),
urlpatterns += path('oidc/op/authz',
                    authz_request,
                    name='spid_oidc_op_authz'),
urlpatterns += path('oidc/op/token',
                    token_request,
                    name='spid_oidc_op_token'),
urlpatterns += path('oidc/op/userinfo',
                    userinfo_request,
                    name='spid_oidc_op_userinfo'),
