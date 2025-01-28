<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class VerifyEmailRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'email' => ['required', 'email', 'exists:users,email'],
            'code' => ['required', 'string', 'size:6']
        ];
    }

    public function messages(): array
    {
        return [
            'email.exists' => 'We could not find a user with that email address.',
            'code.size' => 'The verification code must be 6 characters.'
        ];
    }
} 