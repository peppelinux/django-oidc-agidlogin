from django.urls import path

from . views import oidc_rp_begin



urlpatterns = []
urlpatterns += path('rp/begin', oidc_rp_begin, name='jwtconnect_oidc_rp_begin'),
