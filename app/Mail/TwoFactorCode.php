<?php

namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;

class TwoFactorCode extends Mailable
{
    use Queueable, SerializesModels;

    protected string $code;

    public function __construct(string $code)
    {
        $this->code = $code;
    }

    public function build()
    {
        return $this->subject('Two-Factor Authentication Code - ' . config('app.name'))
            ->markdown('emails.auth.two-factor-code', [
                'code' => $this->code
            ]);
    }
} 