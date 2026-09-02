"""Minimal Django settings so the extension form can be tested without edx-platform."""

SECRET_KEY = "test-only"

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "epp_registration_captcha",
]

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}

USE_TZ = True

# Feature defaults exercised by the tests (individual tests override as needed).
EPP_ENABLE_REGISTRATION_RECAPTCHA = True
RECAPTCHA_PRIVATE_KEY = "test-secret"
RECAPTCHA_PUBLIC_KEY = "test-site-key"
