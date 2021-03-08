from django.urls import path

from . views import oidc_rp_begin



urlpatterns = []
urlpatterns += path('sp/begin', oidc_rp_begin, name='jwtconnect_oidc_rp_begin'),
