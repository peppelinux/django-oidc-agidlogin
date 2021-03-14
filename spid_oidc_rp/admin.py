import json

from django.contrib import admin
from django.utils.safestring import mark_safe

from . models import OidcAuthenticationRequest, OidcAuthenticationToken


def html_json_preview(value):
    msg = json.loads(value or '{}')
    dumps = json.dumps(msg, indent=2)
    return mark_safe(dumps.replace('\n', '<br>').replace('\s', '&nbsp'))


class OidcAuthenticationTokenInline(admin.TabularInline):
    model = OidcAuthenticationToken
    extra = 0
    max_num = 1


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
                       'code_verifier',
                       'code_challenge',
                       'code_challenge_method',
                       'successful',
                       'json_preview',
                       'authz_url',
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
                    'endpoint',
                    'code_verifier',
                    'code_challenge',
                    'code_challenge_method',
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
        ('Previews',
            {
                'fields': (
                    'json_preview',
                    'authz_url',
                    'jwks_preview',
                    'provider_configuration_preview',
                ),
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
