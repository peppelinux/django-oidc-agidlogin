# Generated by Django 3.1.6 on 2021-03-16 16:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('spid_oidc_rp', '0003_auto_20210316_1352'),
    ]

    operations = [
        migrations.AlterField(
            model_name='oidcauthenticationrequest',
            name='client_id',
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name='oidcauthenticationrequest',
            name='issuer',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='oidcauthenticationrequest',
            name='issuer_id',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='oidcauthenticationrequest',
            name='state',
            field=models.CharField(default='state-is-unique', max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name='oidcauthenticationtoken',
            name='code',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='oidcauthenticationtoken',
            name='scope',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='oidcauthenticationtoken',
            name='token_type',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]