<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class UpdateUserRequest extends FormRequest
{
    public function authorize()
    {
        return auth()->user()->is_admin;
    }

    public function rules()
    {
        return [
            'is_admin' => 'required|boolean',
            'is_active' => 'sometimes|boolean', 
        ];
    }
} 