"""Unit tests for RegistrationCaptchaForm. siteverify and DNS lookups are always mocked."""

from unittest import mock

import dns.exception
import dns.resolver
import pytest
import requests

from epp_registration_captcha.forms import RegistrationCaptchaForm

TARGET = "epp_registration_captcha.forms.requests.post"
DNS_TARGET = "epp_registration_captcha.forms.dns.resolver.resolve"


def _mock_response(payload):
    resp = mock.Mock()
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    return resp


def test_valid_token_passes():
    with mock.patch(TARGET, return_value=_mock_response({"success": True})) as post:
        form = RegistrationCaptchaForm(data={"recaptcha_token": "good-token"})
        assert form.is_valid(), form.errors
    post.assert_called_once()
    assert post.call_args.kwargs["data"]["response"] == "good-token"


def test_rejected_token_is_invalid():
    payload = {"success": False, "error-codes": ["invalid-input-response"]}
    with mock.patch(TARGET, return_value=_mock_response(payload)):
        form = RegistrationCaptchaForm(data={"recaptcha_token": "bad-token"})
        assert not form.is_valid()
        assert "recaptcha_token" in form.errors


def test_missing_token_is_invalid_without_calling_google():
    with mock.patch(TARGET) as post:
        form = RegistrationCaptchaForm(data={})
        assert not form.is_valid()
        assert "recaptcha_token" in form.errors
    post.assert_not_called()


def test_network_error_fails_closed():
    with mock.patch(TARGET, side_effect=requests.Timeout("boom")):
        form = RegistrationCaptchaForm(data={"recaptcha_token": "good-token"})
        assert not form.is_valid()
        assert "recaptcha_token" in form.errors


def test_missing_secret_fails_closed(settings):
    settings.RECAPTCHA_PRIVATE_KEY = ""
    with mock.patch(TARGET) as post:
        form = RegistrationCaptchaForm(data={"recaptcha_token": "good-token"})
        assert not form.is_valid()
    post.assert_not_called()


def test_low_v3_score_is_invalid(settings):
    settings.RECAPTCHA_MIN_SCORE = 0.5
    payload = {"success": True, "score": 0.1}
    with mock.patch(TARGET, return_value=_mock_response(payload)):
        form = RegistrationCaptchaForm(data={"recaptcha_token": "good-token"})
        assert not form.is_valid()
        assert "recaptcha_token" in form.errors


def test_high_v3_score_passes(settings):
    settings.RECAPTCHA_MIN_SCORE = 0.5
    payload = {"success": True, "score": 0.9}
    with mock.patch(TARGET, return_value=_mock_response(payload)):
        form = RegistrationCaptchaForm(data={"recaptcha_token": "good-token"})
        assert form.is_valid(), form.errors


def test_kill_switch_disables_verification(settings):
    settings.EPP_ENABLE_REGISTRATION_RECAPTCHA = False
    with mock.patch(TARGET) as post:
        form = RegistrationCaptchaForm(data={})
        assert form.is_valid(), form.errors
    post.assert_not_called()


@pytest.mark.parametrize("header,expected", [("1.2.3.4, 5.6.7.8", "1.2.3.4")])
def test_forwarded_for_ip_is_first_hop(header, expected):
    req = mock.Mock()
    req.META = {"HTTP_X_FORWARDED_FOR": header, "REMOTE_ADDR": "9.9.9.9"}
    with mock.patch(TARGET, return_value=_mock_response({"success": True})) as post, mock.patch(
        "epp_registration_captcha.forms.get_current_request", return_value=req
    ):
        form = RegistrationCaptchaForm(data={"recaptcha_token": "good-token"})
        assert form.is_valid(), form.errors
    assert post.call_args.kwargs["data"]["remoteip"] == expected


def test_save_satisfies_do_create_account_contract():
    """
    Reproduces common.djangoapps.student.helpers.do_create_account's usage verbatim:

        custom_model = custom_form.save(commit=False)
        custom_model.user = user
        custom_model.save()

    A plain forms.Form has no .save() at all, which is exactly what broke registration
    in production (AttributeError: 'RegistrationCaptchaForm' object has no attribute 'save').
    """
    with mock.patch(TARGET, return_value=_mock_response({"success": True})):
        form = RegistrationCaptchaForm(data={"recaptcha_token": "good-token"})
        assert form.is_valid(), form.errors

    custom_model = form.save(commit=False)
    custom_model.user = object()  # do_create_account assigns the freshly created User here
    custom_model.save()  # must not raise


def _mock_answer(count=1):
    return [mock.Mock()] * count


def test_email_with_mx_record_passes(settings):
    settings.EPP_ENABLE_REGISTRATION_RECAPTCHA = False
    with mock.patch(DNS_TARGET, return_value=_mock_answer()) as resolve:
        form = RegistrationCaptchaForm(data={"email": "student@example.com"})
        assert form.is_valid(), form.errors
    resolve.assert_called_once_with("example.com", "MX", lifetime=mock.ANY)


def test_email_without_mx_falls_back_to_a_record(settings):
    settings.EPP_ENABLE_REGISTRATION_RECAPTCHA = False

    def side_effect(domain, record_type, lifetime):  # noqa: ARG001
        if record_type == "MX":
            raise dns.resolver.NoAnswer()
        return _mock_answer()

    with mock.patch(DNS_TARGET, side_effect=side_effect) as resolve:
        form = RegistrationCaptchaForm(data={"email": "student@example.com"})
        assert form.is_valid(), form.errors
    assert resolve.call_count == 2


def test_email_domain_does_not_exist_is_invalid(settings):
    settings.EPP_ENABLE_REGISTRATION_RECAPTCHA = False
    with mock.patch(DNS_TARGET, side_effect=dns.resolver.NXDOMAIN()):
        form = RegistrationCaptchaForm(data={"email": "student@asdasdqwe123nonexistent.com"})
        assert not form.is_valid()
        assert "email" in form.errors


def test_email_domain_with_no_mx_and_no_a_is_invalid(settings):
    settings.EPP_ENABLE_REGISTRATION_RECAPTCHA = False

    def side_effect(domain, record_type, lifetime):  # noqa: ARG001
        if record_type == "MX":
            raise dns.resolver.NoAnswer()
        raise dns.resolver.NXDOMAIN()

    with mock.patch(DNS_TARGET, side_effect=side_effect):
        form = RegistrationCaptchaForm(data={"email": "student@example.com"})
        assert not form.is_valid()
        assert "email" in form.errors


def test_dns_timeout_fails_open(settings):
    settings.EPP_ENABLE_REGISTRATION_RECAPTCHA = False
    with mock.patch(DNS_TARGET, side_effect=dns.exception.Timeout()):
        form = RegistrationCaptchaForm(data={"email": "student@example.com"})
        assert form.is_valid(), form.errors


def test_dns_no_nameservers_fails_open(settings):
    settings.EPP_ENABLE_REGISTRATION_RECAPTCHA = False
    with mock.patch(DNS_TARGET, side_effect=dns.resolver.NoNameservers()):
        form = RegistrationCaptchaForm(data={"email": "student@example.com"})
        assert form.is_valid(), form.errors


def test_email_domain_check_kill_switch(settings):
    settings.EPP_ENABLE_REGISTRATION_RECAPTCHA = False
    settings.EPP_ENABLE_EMAIL_DOMAIN_CHECK = False
    with mock.patch(DNS_TARGET) as resolve:
        form = RegistrationCaptchaForm(data={"email": "student@asdasdqwe123nonexistent.com"})
        assert form.is_valid(), form.errors
    resolve.assert_not_called()


def test_malformed_email_value_skips_dns_lookup(settings):
    settings.EPP_ENABLE_REGISTRATION_RECAPTCHA = False
    with mock.patch(DNS_TARGET) as resolve:
        form = RegistrationCaptchaForm(data={"email": "not-an-email"})
        # Django's own EmailField format validation rejects it; we never reach clean_email's
        # DNS check for a value with no "@".
        assert not form.is_valid()
    resolve.assert_not_called()


def test_save_contract_still_holds_with_email_field(settings):
    settings.EPP_ENABLE_REGISTRATION_RECAPTCHA = False
    with mock.patch(DNS_TARGET, return_value=_mock_answer()):
        form = RegistrationCaptchaForm(data={"email": "student@example.com"})
        assert form.is_valid(), form.errors

    custom_model = form.save(commit=False)
    custom_model.user = object()
    custom_model.save()
