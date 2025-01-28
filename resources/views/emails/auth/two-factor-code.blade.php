@component('mail::message')
# Two-Factor Authentication Code

Your two-factor authentication code is: **{{ $code }}**

This code will expire in 10 minutes.

If you did not request this code, please ignore this email.

Thanks,<br>
{{ config('app.name') }}
@endcomponent 