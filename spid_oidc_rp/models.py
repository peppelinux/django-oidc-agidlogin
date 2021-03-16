import json
import logging

from django.db import models
from django.utils.safestring import mark_safe

from . utils import decode_token, get_issuer_keyjar

logger = logging.getLogger(__name__)


class OidcAuthenticationRequest(models.Model):
    client_id = models.CharField(max_length=256)
    state = models.CharField(max_length=256,
                             unique=True, default='state-is-unique')
    endpoint = models.URLField(blank=True, null=True)
    issuer = models.CharField(max_length=256, blank=True, null=True)
    issuer_id = models.CharField(max_length=256, blank=True, null=True)
    jwks = models.TextField(blank=True, null=True)
    json = models.TextField(blank=True, null=True)
    successful = models.BooleanField(default=False)
    provider_configuration = models.TextField(blank=True, null=True)

    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'{self.client_id} {self.state} to {self.endpoint}'

    def get_provider_keyjar(self):
        jwks = json.loads(self.jwks)
        keyjar = get_issuer_keyjar(jwks, self.issuer)
        return keyjar


class OidcAuthenticationToken(models.Model):
    authz_request = models.ForeignKey(OidcAuthenticationRequest,
                                      on_delete=models.CASCADE)
    code = models.CharField(max_length=256, blank=True, null=True)
    access_token = models.TextField(blank=True, null=True)
    id_token = models.TextField(blank=True, null=True)

    scope = models.CharField(max_length=256, blank=True, null=True)
    token_type = models.CharField(max_length=256, blank=True, null=True)
    expires_in = models.IntegerField(blank=True, null=True)

    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'{self.authz_request} {self.code}'

    @property
    def access_token_preview(self):
        keyjar = self.authz_request.get_provider_keyjar()
        try:
            msg = decode_token(self.access_token, keyjar)
            dumps = json.dumps(msg, indent=2)
            return mark_safe(dumps.replace('\n', '<br>').replace('\s', '&nbsp'))
        except Exception as e:
            logger.tracelog(e)

    @property
    def id_token_preview(self):
        keyjar = self.authz_request.get_provider_keyjar()
        try:
            msg = decode_token(self.id_token, keyjar)
            dumps = json.dumps(msg, indent=2)
            return mark_safe(dumps.replace('\n', '<br>').replace('\s', '&nbsp'))
        except Exception as e:
            logger.tracelog(e)
