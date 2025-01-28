<?php

namespace App\Notifications;

use Illuminate\Notifications\Notification;
use Illuminate\Notifications\Messages\MailMessage;

class VerifyEmail extends Notification
{
    protected string $code;

    public function __construct(string $code)
    {
        $this->code = $code;
    }

    public function via($notifiable): array
    {
        return ['mail'];
    }

    public function toMail($notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject('Verify Your Email - ' . config('app.name'))
            ->greeting('Hello!')
            ->line('Your verification code is: ' . $this->code)
            ->line('This code will expire in 60 minutes.')
            ->line('If you did not create an account, no further action is required.');
    }
} 