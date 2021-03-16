from django.urls import path

from . views import (oidc_rpinitiated_logout,
                     AgidOidcRpBeginView,
                     AgidOidcRpCallbackEchoAttributes,
                     AgidOidcRpCallbackView)

app_name = "spid_oidc_rp"
urlpatterns = []
urlpatterns += path('oidc/rp/begin',
                    AgidOidcRpBeginView.as_view(),
                    name='spid_oidc_rp_begin'),
urlpatterns += path('oidc/rp/callback',
                    AgidOidcRpCallbackView.as_view(),
                    name='spid_oidc_rp_callback'),
urlpatterns += path('echo_attributes',
                    AgidOidcRpCallbackEchoAttributes.as_view(),
                    name='spid_oidc_rp_echo_attributes'),

urlpatterns += path('oidc/rpinitiated_logout',
                    oidc_rpinitiated_logout,
                    name='spid_oidc_rpinitiated_logout'),
