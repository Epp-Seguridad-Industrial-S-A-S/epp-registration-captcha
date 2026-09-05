"""
Registration extension form that verifies a Google reCAPTCHA token server-side and
checks that the registration email's domain can actually receive mail.

Wire it up in the LMS settings::

    REGISTRATION_EXTENSION_FORM = "epp_registration_captcha.forms.RegistrationCaptchaForm"
    RECAPTCHA_PRIVATE_KEY = "<secret key>"          # used here (siteverify)
    RECAPTCHA_PUBLIC_KEY = "<site key>"             # used by the authn MFE only
    EPP_ENABLE_REGISTRATION_RECAPTCHA = True        # kill switch
    # RECAPTCHA_MIN_SCORE = 0.5                     # only if you switch to reCAPTCHA v3
    EPP_ENABLE_EMAIL_DOMAIN_CHECK = True            # kill switch for the MX/A check

edx-platform instantiates this form with ``data=params`` (the full registration POST
body) and calls ``is_valid()`` from ``do_create_account``. ``recaptcha_token`` and
``email`` are ``required=False`` and hidden, so neither is advertised in
``GET /api/user/v1/account/registration/`` but both are still validated on POST.
A failure surfaces to the MFE as ``HTTP 400 {"<field>": [{"user_message": ...}]}``.
Declaring a field literally named ``email`` here does not collide with the platform's
own core ``email`` field: ``RegistrationFormFactory.get_registration_form()`` treats
``email`` as a default field first, so this extension form's copy never reaches the GET
schema -- it only rides along for POST-time validation, exactly like ``recaptcha_token``.

On success, ``common.djangoapps.student.helpers.do_create_account`` unconditionally does::

    custom_model = custom_form.save(commit=False)
    custom_model.user = user
    custom_model.save()

so ``REGISTRATION_EXTENSION_FORM`` classes must implement that ``save(commit=False)``
contract even when there is nothing to persist -- see ``save()`` below.
"""

import logging

import dns.exception
import dns.resolver
import requests
from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

try:  # edx-platform ships django-crum; degrade gracefully if it is ever missing.
    from crum import get_current_request
except ImportError:  # pragma: no cover

    def get_current_request():
        return None


log = logging.getLogger(__name__)

SITEVERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"
DEFAULT_TIMEOUT = 10
DEFAULT_DNS_TIMEOUT = 5


def _feature_enabled():
    return bool(getattr(settings, "EPP_ENABLE_REGISTRATION_RECAPTCHA", True))


def _domain_check_enabled():
    return bool(getattr(settings, "EPP_ENABLE_EMAIL_DOMAIN_CHECK", True))


class DomainLookupError(Exception):
    """The DNS lookup itself could not be completed (timeout, no nameservers, etc.).

    This does NOT mean the domain is invalid -- callers must treat it as "unknown" and
    fail open, since it usually reflects a transient problem on our side, not the user's.
    """


def domain_can_receive_mail(domain, timeout=DEFAULT_DNS_TIMEOUT):
    """Return True if `domain` publishes an MX record, or an A/AAAA record as the
    RFC 5321 fallback for domains with no MX. Raises DomainLookupError if the lookup
    itself fails (as opposed to resolving to "no such domain")."""
    try:
        try:
            return len(dns.resolver.resolve(domain, "MX", lifetime=timeout)) > 0
        except dns.resolver.NoAnswer:
            # No MX published; RFC 5321 permits falling back to the A/AAAA record.
            return len(dns.resolver.resolve(domain, "A", lifetime=timeout)) > 0
    except dns.resolver.NXDOMAIN:
        return False
    except (dns.exception.Timeout, dns.resolver.NoNameservers, OSError) as exc:
        raise DomainLookupError(str(exc)) from exc


def _client_ip():
    request = get_current_request()
    if request is None:
        return None
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


class _NothingToPersist:
    """Stand-in "model" for do_create_account's custom_form.save(commit=False) contract.

    We only need the token for verification, not storage, so `.user` is a plain
    attribute assignment and `.save()` is a no-op.
    """

    def save(self, *args, **kwargs):
        pass


class RegistrationCaptchaForm(forms.Form):
    """Validate the reCAPTCHA token (``recaptcha_token``) and the registration email's
    domain (``email``), both injected by the forked authn MFE / the platform's own
    registration payload."""

    recaptcha_token = forms.CharField(
        required=False,
        widget=forms.HiddenInput,
        label=_("Captcha"),
    )
    email = forms.EmailField(
        required=False,
        widget=forms.HiddenInput,
        label=_("Email"),
    )

    def save(self, commit=True):  # noqa: ARG002 - required by do_create_account's custom_form contract
        return _NothingToPersist()

    def clean_email(self):
        email = (self.cleaned_data.get("email") or "").strip()
        if not email or "@" not in email:
            # Malformed values are already rejected by the platform's own core email
            # field; nothing more for us to check here.
            return email

        if not _domain_check_enabled():
            return email

        domain = email.rsplit("@", 1)[-1]
        try:
            can_receive_mail = domain_can_receive_mail(domain)
        except DomainLookupError:
            # Fail open: a DNS hiccup on our side must not block a real signup.
            log.warning("MX/A lookup failed for domain %s; allowing registration", domain)
            return email

        if not can_receive_mail:
            log.info("Rejecting registration: domain %s has no MX/A record", domain)
            raise ValidationError(
                _("We couldn't verify that '%(domain)s' can receive email. " "Please check your email address.")
                % {"domain": domain}
            )
        return email

    def clean_recaptcha_token(self):
        if not _feature_enabled():
            return ""

        token = (self.cleaned_data.get("recaptcha_token") or "").strip()
        if not token:
            raise ValidationError(_("Please complete the CAPTCHA challenge and try again."))

        secret = getattr(settings, "RECAPTCHA_PRIVATE_KEY", "") or ""
        if not secret:
            log.error(
                "RECAPTCHA_PRIVATE_KEY is not configured while "
                "EPP_ENABLE_REGISTRATION_RECAPTCHA is on; rejecting registration."
            )
            raise ValidationError(_("CAPTCHA verification is unavailable. Please contact support."))

        try:
            response = requests.post(
                SITEVERIFY_URL,
                data={"secret": secret, "response": token, "remoteip": _client_ip()},
                timeout=getattr(settings, "RECAPTCHA_TIMEOUT", DEFAULT_TIMEOUT),
            )
            response.raise_for_status()
            result = response.json()
        except (requests.RequestException, ValueError):
            # Fail closed: a bot must not slip through because siteverify was slow/down.
            log.exception("reCAPTCHA siteverify request failed")
            raise ValidationError(_("Could not verify the CAPTCHA. Please try again."))

        if not result.get("success"):
            log.warning("reCAPTCHA rejected the token: %s", result.get("error-codes"))
            raise ValidationError(_("CAPTCHA verification failed. Please try again."))

        min_score = getattr(settings, "RECAPTCHA_MIN_SCORE", None)
        if min_score is not None and "score" in result and result["score"] < float(min_score):
            log.warning("reCAPTCHA score %s below threshold %s", result["score"], min_score)
            raise ValidationError(_("CAPTCHA verification failed. Please try again."))

        return token
