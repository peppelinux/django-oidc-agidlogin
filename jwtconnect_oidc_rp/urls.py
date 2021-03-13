import os
from django.urls import path

from . views import *



urlpatterns = []

if os.environ.get('ROHE_TEST'):
    urlpatterns += path('rp/begin',
                        OidcRpBeginView.as_view(),
                        name='jwtconnect_oidc_rp_begin'),
    urlpatterns += path('callback',
                        OidcRpCallbackView.as_view(),
                        name='jwtconnect_oidc_rp_callback'),

else:
    urlpatterns += path('rp/begin',
                        AgidOidcRpBeginView.as_view(),
                        name='jwtconnect_oidc_rp_begin'),
    urlpatterns += path('callback',
                        AgidOidcRpCallbackView.as_view(),
                        name='jwtconnect_oidc_rp_callback'),
