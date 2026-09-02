"""Unit tests for RegistrationCaptchaForm. siteverify is always mocked."""

from unittest import mock

import pytest
import requests

from epp_registration_captcha.forms import RegistrationCaptchaForm

TARGET = "epp_registration_captcha.forms.requests.post"


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
