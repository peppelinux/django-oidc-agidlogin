"""example URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.contrib import admin
from django.urls import path, include

ADMIN_PATH = getattr(settings, 'ADMIN_PATH', 'admin')

urlpatterns = [
    path(f'{ADMIN_PATH}/', admin.site.urls),
]

if 'spid_oidc_rp' in settings.INSTALLED_APPS:
    urlpatterns += path('',
                        include(('spid_oidc_rp.urls', 'rp'), namespace="spid_oidc_rp"),
                        name="spid_oidc_rp"),
