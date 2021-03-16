import json
import logging

from django.contrib import admin
from django.utils.safestring import mark_safe

from . models import OidcAuthenticationRequest, OidcAuthenticationToken

logger = logging.getLogger(__name__)


def html_json_preview(value):
    msg = json.loads(value or '{}')
    dumps = json.dumps(msg, indent=2)
    return mark_safe(dumps.replace('\n', '<br>').replace('\s', '&nbsp'))


class OidcAuthenticationTokenInline(admin.StackedInline):
    model = OidcAuthenticationToken
    extra = 0
    max_num = 1
    readonly_fields = ('scope',
                       'expires_in',
                       'token_type',
                       'code',
                       'access_token',
                       'id_token',
                       'access_token_preview',
                       'id_token_preview')


@admin.register(OidcAuthenticationRequest)
class OidcAuthenticationRequestAdmin(admin.ModelAdmin):
    search_fields = ('endpoint', 'state', 'client_id')
    list_display = ('client_id', 'state', 'endpoint', 'created', 'modified')
    list_filter = ('created', 'endpoint')
    inlines = (OidcAuthenticationTokenInline, )
    readonly_fields = ('issuer',
                       'client_id',
                       'state',
                       'endpoint',
                       'successful',
                       'json_preview',
                       'jwks_preview',
                       'provider_configuration_preview',
                       'created',
                       'modified')
    exclude = ('issuer_id', 'json', 'provider_configuration', 'jwks')
    fieldsets = (
        (None,
            {
                'fields': (
                    'issuer',
                    'client_id',
                    'state',
                    'endpoint'
                )
            }
         ),
        ('Status',
            {
                'fields': (
                    'successful',
                    'created',
                    'modified',
                )
            }
         ),
        ('Authorization request previews',
            {
                'fields': (
                    'json_preview',
                    'jwks_preview',
                ),
                'classes': ('collapse',),
            }
         ),
        ('Provider Discovery result',
            {
                'fields': ('provider_configuration_preview',),
                'classes': ('collapse',),
            }
         )
    )

    def json_preview(self, obj):
        return html_json_preview(obj.json)
    json_preview.short_description = 'Authentication Request data'

    def provider_configuration_preview(self, obj):
        return html_json_preview(obj.provider_configuration)
    provider_configuration_preview.short_description = 'provider configuration'

    def jwks_preview(self, obj):
        return html_json_preview(obj.jwks)
    jwks_preview.short_description = 'jwks'
