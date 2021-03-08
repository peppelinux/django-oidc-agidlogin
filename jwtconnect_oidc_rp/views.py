import logging

from django.conf import settings
from django.http import (Http404,
                         HttpResponseRedirect)
from django.shortcuts import render
from jwtconnect_oidc_rp.utils import get_rph


logger = logging.getLogger(__name__)


def oidc_rp_begin(request):
    rph = get_rph()
    return HttpResponseRedirect(info['url'])
