Change Log
##########

0.1.1
=====

* Fix ``AttributeError: 'RegistrationCaptchaForm' object has no attribute 'save'`` that broke
  every registration in production. ``common.djangoapps.student.helpers.do_create_account``
  unconditionally calls ``custom_form.save(commit=False)`` then sets ``.user`` and calls
  ``.save()`` on the result, even though the extension form is only used for validation here.
  Added a no-op ``save()`` returning a throwaway object that satisfies that contract.

0.1.0
=====

* Initial release: ``RegistrationCaptchaForm`` registration extension form that verifies
  a Google reCAPTCHA token against ``siteverify`` server-side, with a fail-closed policy
  and an ``EPP_ENABLE_REGISTRATION_RECAPTCHA`` kill switch.
