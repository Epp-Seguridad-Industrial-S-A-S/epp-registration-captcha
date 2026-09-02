"""App configuration for epp_registration_captcha.

Registering this app in ``INSTALLED_APPS`` is optional: ``REGISTRATION_EXTENSION_FORM``
only needs :mod:`epp_registration_captcha.forms` to be importable. The ``AppConfig`` is
kept so translations and app-scoped checks work when it is installed.
"""

from django.apps import AppConfig


class EppRegistrationCaptchaConfig(AppConfig):
    name = "epp_registration_captcha"
    verbose_name = "EPP registration reCAPTCHA"
    default_auto_field = "django.db.models.BigAutoField"
