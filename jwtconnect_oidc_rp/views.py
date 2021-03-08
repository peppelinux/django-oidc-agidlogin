import logging

from django.conf import settings
from django.http import (Http404,
                         HttpResponseRedirect)
from django.shortcuts import render
from jwtconnect_oidc_rp.utils import get_rph

from . exceptions import MisconfiguredClientIssuer


logger = logging.getLogger(__name__)


def oidc_rp_begin(request):
    rph = get_rph()

    available_issuers = settings.JWTCONN_OIDC_RP['clients']
    available_issuers_len = len(available_issuers)
    if available_issuers_len > 1:
        issuer_id = request.GET.get('issuer_id') 
    elif available_issuers_len == 1:
        issuer_id = available_issuers.keys()[0]
    else:
        raise MisconfiguredClientIssuer('No available issuers found')

    info = rph.begin(issuer_id)
    return HttpResponseRedirect(info['url'])
