# epp-registration-captcha

Server-side Google reCAPTCHA verification for the Open edX self-registration
("autoregistro") flow of the **udesst** distribution (Epp Seguridad Industrial S.A.S.).

It is a Django app meant to be **installed into the edx-platform (LMS) image**, not run
standalone — same model as `shoppingcart-app`.

## What it does

`epp_registration_captcha.forms.RegistrationCaptchaForm` is a registration *extension
form*. edx-platform loads it from `settings.REGISTRATION_EXTENSION_FORM`, instantiates it
with the registration POST body, and calls `is_valid()` while creating the account. The
form takes a single hidden field, `recaptcha_token`, and verifies it against Google's
`siteverify` endpoint using `settings.RECAPTCHA_PRIVATE_KEY`. On failure the registration
API responds `HTTP 400` with `{"recaptcha_token": [{"user_message": "..."}]}`.

The token itself is produced by the **forked `frontend-app-authn`** MFE, which renders the
reCAPTCHA widget and sends the token as `recaptchaToken` (snake-cased to `recaptcha_token`
by the MFE before the request).

## Settings

| Setting | Purpose |
|---|---|
| `REGISTRATION_EXTENSION_FORM` | must be `"epp_registration_captcha.forms.RegistrationCaptchaForm"` |
| `RECAPTCHA_PRIVATE_KEY` | Google reCAPTCHA **secret** key (used here) |
| `RECAPTCHA_PUBLIC_KEY` | Google reCAPTCHA **site** key (used by the MFE via `MFE_CONFIG`) |
| `EPP_ENABLE_REGISTRATION_RECAPTCHA` | kill switch, default `True`. When `False` the form is a no-op |
| `RECAPTCHA_MIN_SCORE` | optional; only meaningful for reCAPTCHA **v3** |
| `RECAPTCHA_TIMEOUT` | optional siteverify timeout in seconds (default `10`) |

All of these are injected by `tutor-epp-theme-plugins` (`tutorindigo/plugin.py`) from the
`INDIGO_RECAPTCHA_*` Tutor config values.

**Fail-closed:** if the feature is enabled but the secret is missing, or siteverify is
unreachable, registration is rejected rather than allowed through.

## Install (done by the Tutor plugin, shown here for reference)

```
pip install 'git+https://github.com/Epp-Seguridad-Industrial-S-A-S/epp-registration-captcha.git@v0.1.0'
```

## Tests

```
pip install -r requirements/test.in
pytest
```
