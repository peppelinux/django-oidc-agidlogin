from django.db import models



class OidcAuthenticationRequest(models.Model):
    client_id = models.CharField(max_length=256)
    state = models.CharField(max_length=256,
                             unique=True, default='state-is-unique')
    endpoint = models.URLField(blank=True, null=True)
    issuer = models.CharField(max_length=256, blank=True, null=True)
    issuer_id =  models.CharField(max_length=256, blank=True, null=True)
    code_challenge = models.CharField(
                                max_length=256, blank=True, null=True)
    code_challenge_method = models.CharField(
                                        max_length=256, blank=True, null=True)
    code_verifier = models.CharField(
                                max_length=256, blank=True, null=True)
    authz_url = models.URLField(blank=True, null=True)
    jwks = models.TextField(blank=True, null=True)
    json = models.TextField(blank=True, null=True)
    successful = models.BooleanField(default=False)
    provider_configuration = models.TextField(blank=True, null=True)

    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'{self.client_id} {self.state} to {self.endpoint}'


class OidcAuthenticationToken(models.Model):
    authz_request = models.ForeignKey(OidcAuthenticationRequest,
                                      on_delete = models.CASCADE)
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
