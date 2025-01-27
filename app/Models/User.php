<?php

namespace App\Models;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Passport\HasApiTokens;
use App\Notifications\VerifyEmail;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Log;

/**
 * @OA\Schema(
 *     schema="User",
 *     required={"name", "email", "phone", "password"},
 *     @OA\Property(property="id", type="integer", format="int64", example=1),
 *     @OA\Property(property="name", type="string", example="John Doe"),
 *     @OA\Property(property="email", type="string", format="email", example="user@example.com"),
 *     @OA\Property(property="phone", type="string", example="+201234567890"),
 *     @OA\Property(property="avatar", type="string", nullable=true, example="avatars/user-avatar.jpg"),
 *     @OA\Property(property="is_admin", type="boolean", example=false),
 *     @OA\Property(property="email_verified_at", type="string", format="date-time", nullable=true),
 *     @OA\Property(property="created_at", type="string", format="date-time"),
 *     @OA\Property(property="updated_at", type="string", format="date-time")
 * )
 */
class User extends Authenticatable implements MustVerifyEmail
{
    /** @use HasFactory<\Database\Factories\UserFactory> */
    use HasApiTokens, HasFactory, Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'name',
        'email',
        'phone',
        'password',
        'is_admin',
        'avatar'
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var list<string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
        'password' => 'hashed',
        'is_admin' => 'boolean',
        'is_active' => 'boolean'
    ];

    public function sendEmailVerificationNotification()
    {
        try {
            // Generate code
            $code = strtoupper(Str::random(6));
            
            // Save code
            EmailVerificationCode::updateOrCreate(
                ['user_id' => $this->id],
                [
                    'code' => $code,
                    'expires_at' => now()->addMinutes(60)
                ]
            );

            // Send email
            $this->notify(new VerifyEmail($code));
            
        } catch (\Exception $e) {
            Log::error('Email verification error: ' . $e->getMessage());
            throw $e;
        }
    }
}
