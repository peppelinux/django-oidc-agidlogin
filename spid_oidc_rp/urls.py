from django.urls import path

from . views import AgidOidcRpBeginView, AgidOidcRpCallbackView


urlpatterns = []
urlpatterns += path('oidc/spid/begin',
                    AgidOidcRpBeginView.as_view(),
                    name='spid_oidc_rp_begin'),
urlpatterns += path('callback',
                    AgidOidcRpCallbackView.as_view(),
                    name='spid_oidc_rp_callback'),
