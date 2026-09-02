"""
Server-side Google reCAPTCHA verification for the Open edX self-registration flow.

The public entry point is :class:`epp_registration_captcha.forms.RegistrationCaptchaForm`,
wired into edx-platform through ``settings.REGISTRATION_EXTENSION_FORM``.
"""

__version__ = "0.1.0"
