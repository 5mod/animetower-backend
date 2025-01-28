<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\ChangePasswordRequest;
use App\Http\Requests\ForgotPasswordRequest;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RefreshTokenRequest;
use App\Http\Requests\RegisterRequest;
use App\Http\Requests\ResetPasswordRequest;
use App\Models\User;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Database\QueryException;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Laravel\Passport\Exceptions\OAuthServerException;
use Exception;
use App\Mail\PasswordResetMail;
use App\Notifications\PasswordChanged;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\URL;
use Illuminate\Auth\Events\Verified;
use Illuminate\Http\Request;
use App\Models\EmailVerificationCode;
use App\Notifications\VerifyEmail;
use App\Http\Requests\VerifyEmailRequest;
use App\Http\Requests\ResendVerificationRequest;
use App\Models\PasswordResetCode;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;
use App\Http\Requests\UpdateUserRequest;
use App\Http\Requests\UpdateProfileRequest;
use Illuminate\Support\Facades\Storage;
use App\Http\Requests\TwoFactorAuthRequest;
use App\Notifications\TwoFactorCode;
use App\Http\Requests\VerifyOtpRequest;
use App\Mail\TwoFactorCode as TwoFactorCodeMail;

/**
 * @OA\Tag(
 *     name="Authentication",
 *     description="API Endpoints for user authentication"
 * )
 * @OA\Tag(
 *     name="Email Verification",
 *     description="API Endpoints for email verification"
 * )
 * @OA\Tag(
 *     name="Password Management",
 *     description="API Endpoints for password management"
 * )
 */
class AuthController extends Controller
{
    /**
     * @OA\Post(
     *     path="/v1/accounts/login",
     *     tags={"Authentication"},
     *     summary="Login user and get token",
     *     description="Authenticate user and return access token. If 2FA is enabled, two_factor_code is required.",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email","password"},
     *             @OA\Property(property="email", type="string", format="email", example="user@example.com"),
     *             @OA\Property(property="password", type="string", format="password", example="password123"),
     *             @OA\Property(
     *                 property="two_factor_code",
     *                 type="string",
     *                 example="nullable",
     *                 description="Required if 2FA is enabled. Get code from /2fa/send-otp endpoint",
     *                 nullable=true
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Login successful",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Successfully logged in"),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 @OA\Property(
     *                     property="user",
     *                     type="object",
     *                     @OA\Property(property="id", type="integer", example=1),
     *                     @OA\Property(property="name", type="string", example="John Doe"),
     *                     @OA\Property(property="email", type="string", example="user@example.com"),
     *                     @OA\Property(property="phone", type="string", example="+201234567890"),
     *                     @OA\Property(property="email_verified_at", type="string", format="date-time"),
     *                     @OA\Property(property="is_admin", type="boolean", example=false),
     *                     @OA\Property(property="two_factor_enabled", type="boolean", example=true)
     *                 ),
     *                 @OA\Property(property="token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1..."),
     *                 @OA\Property(property="refresh_token", type="string", example="def502..."),
     *                 @OA\Property(property="token_type", type="string", example="Bearer"),
     *                 @OA\Property(property="email_verified", type="boolean", example=true),
     *                 @OA\Property(property="is_admin", type="boolean", example=false)
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Invalid credentials or invalid 2FA code",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="The provided credentials are incorrect.")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="2FA code required or email not verified",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Two-factor authentication code is required"),
     *             @OA\Property(property="requires_2fa", type="boolean", example=true)
     *         )
     *     )
     * )
     */
    public function login(LoginRequest $request): JsonResponse
    {
        try {
            // Verify credentials
            if (!Auth::attempt([
                'email' => $request->email, 
                'password' => $request->password
            ])) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'The provided credentials are incorrect.'
                ], 401);
            }

            $user = Auth::user();

            // Check if user is active
            if (!$user->is_active) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Your account has been deactivated. Please contact support.'
                ], 403);
            }

            // Check if email is verified
            if (!$user->hasVerifiedEmail()) {
                try {
                    // Generate new verification code
                    $code = strtoupper(Str::random(6));
                    
                    // Save verification code
                    EmailVerificationCode::updateOrCreate(
                        ['user_id' => $user->id],
                        [
                            'code' => $code,
                            'expires_at' => now()->addMinutes(60)
                        ]
                    );
                    Log::info('Generated verification code for user: ' . $user->id);

                    try {
                        // Send verification using notification
                        $user->notify(new \App\Notifications\VerifyEmail($code));
                        Log::info('Verification email sent successfully to: ' . $user->email);

                    } catch (\Exception $e) {
                        Log::error('Failed to send verification email: ' . $e->getMessage());
                        return response()->json([
                            'status' => 'error',
                            'message' => 'Failed to send verification email. Please try again.'
                        ], 500);
                    }

                    return response()->json([
                        'status' => 'error',
                        'message' => 'Email not verified. A new verification code has been sent to your email.',
                        'verification_required' => true,
                        'email' => $user->email
                    ], 403);

                } catch (\Exception $e) {
                    Log::error('Email verification error: ' . $e->getMessage());
                    return response()->json([
                        'status' => 'error',
                        'message' => 'Failed to process email verification. Please try again.'
                    ], 500);
                }
            }

            // Handle 2FA
            if ($user->two_factor_enabled) {
                if (!$request->two_factor_code) {
                    try {
                        $code = strtoupper(Str::random(6));
                        
                        $user->update([
                            'two_factor_code' => $code,
                            'two_factor_expires_at' => now()->addMinutes(10)
                        ]);

                        // Send email
                        Mail::to($user)->send(new TwoFactorCodeMail($code));
                        Log::info('2FA code sent successfully to: ' . $user->email);

                        return response()->json([
                            'status' => 'error',
                            'message' => 'Two-factor authentication code is required. Please check your email.',
                            'requires_2fa' => true
                        ], 403);

                    } catch (\Exception $e) {
                        Log::error('Failed to send 2FA code: ' . $e->getMessage());
                        return response()->json([
                            'status' => 'error',
                            'message' => 'Failed to send authentication code. Please try again.'
                        ], 500);
                    }
                }

                if ($user->two_factor_expires_at->isPast()) {
                    return response()->json([
                        'status' => 'error',
                        'message' => 'Two-factor authentication code has expired. Please request a new code.'
                    ], 401);
                }
            }

            try {
                // Clear any existing OTP codes
                $user->update([
                    'two_factor_code' => null,
                    'two_factor_expires_at' => null
                ]);

                // Create token
                $tokenResult = $user->createToken('auth-token');

                // Create refresh token
                $refreshTokenId = Str::random(40);
                DB::table('oauth_refresh_tokens')->insert([
                    'id' => $refreshTokenId,
                    'access_token_id' => $tokenResult->token->id,
                    'revoked' => false,
                    'expires_at' => now()->addDays(30)
                ]);

                return response()->json([
                    'status' => 'success',
                    'message' => 'Successfully logged in',
                    'data' => [
                        'user' => $user,
                        'token' => $tokenResult->accessToken,
                        'refresh_token' => $refreshTokenId,
                        'token_type' => 'Bearer',
                        'email_verified' => true,
                        'is_admin' => $user->is_admin
                    ]
                ]);

            } catch (Exception $e) {
                Log::error('Token creation error: ' . $e->getMessage());
                return response()->json([
                    'status' => 'error',
                    'message' => 'Failed to create authentication token. Please try again.'
                ], 500);
            }

        } catch (Exception $e) {
            Log::error('Login error: ' . $e->getMessage());
            return response()->json([
                'status' => 'error',
                'message' => 'An unexpected error occurred. Please try again later.'
            ], 500);
        }
    }

    /**
     * @OA\Post(
     *     path="/v1/accounts/register",
     *     tags={"Authentication"},
     *     summary="Register a new user",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"name","email","phone","password","password_confirmation","is_admin"},
     *             @OA\Property(property="name", type="string", example="John Doe"),
     *             @OA\Property(property="email", type="string", format="email", example="user@example.com"),
     *             @OA\Property(property="phone", type="string", example="+201234567890"),
     *             @OA\Property(property="password", type="string", format="password", example="password123"),
     *             @OA\Property(property="password_confirmation", type="string", format="password", example="password123"),
     *             @OA\Property(property="is_admin", type="boolean", example=false)
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="User registered successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Successfully registered. Please check your email to verify your account."),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 @OA\Property(property="user", ref="#/components/schemas/User"),
     *                 @OA\Property(property="token", type="string"),
     *                 @OA\Property(property="token_type", type="string", example="Bearer")
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="The email has already been taken.")
     *         )
     *     )
     * )
     */
    public function register(RegisterRequest $request): JsonResponse
    {
        try {
            Log::info('Starting registration for email: ' . $request->email);
            
            // Check if email already exists
            if (User::where('email', $request->email)->exists()) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'This email address is already registered.'
                ], 422);
            }

            try {
                $user = User::create([
                    'name' => $request->name,
                    'email' => $request->email,
                    'phone' => $request->phone,
                    'password' => Hash::make($request->password),
                ]);
                Log::info('User created with ID: ' . $user->id);

            } catch (QueryException $e) {
                Log::error('Database error during user creation: ' . $e->getMessage());
                return response()->json([
                    'status' => 'error',
                    'message' => 'Failed to create user account. Please try again.'
                ], 500);
            }

            try {
                // Generate verification code
                $code = strtoupper(Str::random(6));
                
                EmailVerificationCode::create([
                    'user_id' => $user->id,
                    'code' => $code,
                    'expires_at' => now()->addMinutes(60)
                ]);

                // Send verification email
                $user->notify(new VerifyEmail($code));
                Log::info('Verification email sent successfully');

                return response()->json([
                    'status' => 'success',
                    'message' => 'Successfully registered. Please check your email to verify your account.',
                    'data' => [
                        'user' => $user
                    ]
                ], 201);

            } catch (\Exception $e) {
                Log::error('Failed to send verification email: ' . $e->getMessage());
                return response()->json([
                    'status' => 'error',
                    'message' => 'Account created but failed to send verification email. Please request a new verification code.'
                ], 500);
            }

        } catch (\Exception $e) {
            Log::error('Registration error: ' . $e->getMessage());
            return response()->json([
                'status' => 'error',
                'message' => 'An unexpected error occurred during registration. Please try again.'
            ], 500);
        }
    }

    /**
     * @OA\Get(
     *     path="/v1/accounts/logout",
     *     tags={"Authentication"},
     *     summary="Logout user",
     *     description="Revoke the current access token",
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Successfully logged out",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Successfully logged out")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthenticated",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthenticated")
     *         )
     *     )
     * )
     */
    public function logout(): JsonResponse
    {
        try {
            $user = auth('api')->user();
            
            if (!$user) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'User not found'
                ], 401);
            }

            // Get access token
            $accessToken = $user->token();
            
            // Revoke access token
            DB::table('oauth_access_tokens')
                ->where('id', $accessToken->id)
                ->update(['revoked' => true]);

            // Revoke refresh tokens
            DB::table('oauth_refresh_tokens')
                ->where('access_token_id', $accessToken->id)
                ->update(['revoked' => true]);

            return response()->json([
                'status' => 'success',
                'message' => 'Successfully logged out'
            ]);

        } catch (Exception $e) {
            Log::error('Logout error: ' . $e->getMessage());
            Log::error('Stack trace: ' . $e->getTraceAsString());
            return response()->json([
                'status' => 'error',
                'message' => 'An error occurred while logging out'
            ], 500);
        }
    }

    /**
     * @OA\Get(
     *     path="/v1/accounts/user",
     *     tags={"Authentication"},
     *     summary="Get authenticated user details",
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="User details retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 @OA\Property(property="user", ref="#/components/schemas/User"),
     *                 @OA\Property(property="is_admin", type="boolean", example=false),
     *                 @OA\Property(property="email_verified", type="boolean", example=false)
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthenticated",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthenticated")
     *         )
     *     )
     * )
     */
    public function getUser(): JsonResponse
    {
        try {
            return response()->json([
                'status' => 'success',
                'data' => Auth::user()
            ]);
        } catch (Exception $e) {
            Log::error('Get user error: ' . $e->getMessage());
            return response()->json([
                'status' => 'error',
                'message' => 'An error occurred while fetching user data.'
            ], 500);
        }
    }

    /**
     * @OA\Post(
     *     path="/v1/accounts/token/refresh",
     *     tags={"Authentication"},
     *     summary="Refresh access token",
     *     description="Get a new access token using refresh token",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"refresh_token"},
     *             @OA\Property(property="refresh_token", type="string", example="def502...")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Token refreshed successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Token refreshed successfully"),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 @OA\Property(property="token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1..."),
     *                 @OA\Property(property="token_type", type="string", example="Bearer")
     *             )
     *         )
     *     )
     * )
     */
    public function refreshToken(RefreshTokenRequest $request): JsonResponse
    {
        try {
            $refreshToken = $request->refresh_token;
            
            // Find token in database
            $token = DB::table('oauth_refresh_tokens')
                ->where('id', $refreshToken)
                ->first();

            if (!$token) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Invalid refresh token'
                ], 401);
            }

            // Get user from access token
            $accessToken = DB::table('oauth_access_tokens')
                ->where('id', $token->access_token_id)
                ->first();

            if (!$accessToken) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Invalid access token'
                ], 401);
            }

            $user = User::find($accessToken->user_id);

            if (!$user) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'User not found'
                ], 404);
            }

            // Revoke old tokens
            DB::table('oauth_access_tokens')
                ->where('user_id', $user->id)
                ->update(['revoked' => true]);

            DB::table('oauth_refresh_tokens')
                ->where('access_token_id', $accessToken->id)
                ->update(['revoked' => true]);

            // Create new token
            $newToken = $user->createToken('auth-token');

            return response()->json([
                'status' => 'success',
                'message' => 'Token refreshed successfully',
                'data' => [
                    'token' => $newToken->accessToken,
                    'token_type' => 'Bearer'
                ]
            ]);

        } catch (Exception $e) {
            Log::error('Token refresh error: ' . $e->getMessage());
            return response()->json([
                'status' => 'error',
                'message' => 'An error occurred while refreshing the token'
            ], 500);
        }
    }

    /**
     * @OA\Post(
     *     path="/v1/accounts/password/forgot",
     *     tags={"Password Management"},
     *     summary="Request password reset code",
     *     description="Send a password reset code to user's email",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email"},
     *             @OA\Property(property="email", type="string", format="email", example="user@example.com")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Reset code sent successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Password reset code sent to your email")
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="User not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="User not found")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Failed to send reset code"),
     *             @OA\Property(property="error", type="string")
     *         )
     *     )
     * )
     */
    public function forgotPassword(ForgotPasswordRequest $request): JsonResponse
    {
        try {
            $user = User::where('email', $request->email)->first();
            
            if (!$user) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'User not found'
                ], 404);
            }

            // Generate code
            $code = strtoupper(Str::random(6));
            
            // Save code
            PasswordResetCode::updateOrCreate(
                ['email' => $request->email],
                [
                    'code' => $code,
                    'expires_at' => now()->addMinutes(60)
                ]
            );

            // Send email with code
            Mail::to($user)->send(new PasswordResetMail($code));

            return response()->json([
                'status' => 'success',
                'message' => 'Password reset code sent to your email'
            ]);
        } catch (Exception $e) {
            Log::error('Forgot password error: ' . $e->getMessage());
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to send reset code',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * @OA\Post(
     *     path="/v1/accounts/password/reset",
     *     tags={"Password Management"},
     *     summary="Reset password using code",
     *     description="Reset user's password using the code sent to their email",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email", "code", "password", "password_confirmation"},
     *             @OA\Property(property="email", type="string", format="email", example="user@example.com"),
     *             @OA\Property(property="code", type="string", example="ABC123", description="6-character code sent to email"),
     *             @OA\Property(property="password", type="string", format="password", example="newpassword123", description="Minimum 6 characters"),
     *             @OA\Property(property="password_confirmation", type="string", example="newpassword123")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Password reset successful",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Password has been successfully reset")
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Invalid code",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Invalid or expired reset code")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(
     *                 property="errors",
     *                 type="object",
     *                 @OA\Property(
     *                     property="password",
     *                     type="array",
     *                     @OA\Items(type="string", example="The password must be at least 6 characters.")
     *                 )
     *             )
     *         )
     *     )
     * )
     */
    public function resetPassword(ResetPasswordRequest $request): JsonResponse
    {
        try {
            $resetCode = PasswordResetCode::where('email', $request->email)
                ->where('code', $request->code)
                ->where('expires_at', '>', now())
                ->first();

            if (!$resetCode) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Invalid or expired reset code'
                ], 400);
            }

            $user = User::where('email', $request->email)->first();
            
            // Reset the password
            $user->password = Hash::make($request->password);
            $user->save();

            // Delete the used code
            $resetCode->delete();

            // Revoke all tokens
            $user->tokens()->delete();
            
            // Send notification
            $user->notify(new PasswordChanged);

            return response()->json([
                'status' => 'success',
                'message' => 'Password has been successfully reset'
            ]);
        } catch (Exception $e) {
            Log::error('Reset password error: ' . $e->getMessage());
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to reset password',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * @OA\Post(
     *     path="/v1/accounts/password/change",
     *     tags={"Password Management"},
     *     summary="Change password for authenticated user",
     *     description="Change password for logged-in user requiring current password",
     *     security={{"bearerAuth":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"current_password", "password", "password_confirmation"},
     *             @OA\Property(property="current_password", type="string", example="oldpassword123"),
     *             @OA\Property(property="password", type="string", format="password", example="newpassword123", description="Must be different from current password"),
     *             @OA\Property(property="password_confirmation", type="string", example="newpassword123")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Password changed successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Password successfully changed")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(
     *                 property="errors",
     *                 type="object",
     *                 @OA\Property(
     *                     property="current_password",
     *                     type="array",
     *                     @OA\Items(type="string", example="Your current password is incorrect.")
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthenticated",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthenticated.")
     *         )
     *     )
     * )
     */
    public function changePassword(ChangePasswordRequest $request): JsonResponse
    {
        try {
            $user = Auth::user();
            $user->password = Hash::make($request->password);
            $user->save();

            // Revoke all tokens
            $user->tokens()->delete();
            
            // Send notification
            $user->notify(new PasswordChanged);

            return response()->json([
                'status' => 'success',
                'message' => 'Password successfully changed'
            ]);
        } catch (Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to change password',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * @OA\Post(
     *     path="/v1/accounts/email/verify",
     *     tags={"Email Verification"},
     *     summary="Verify email with code",
     *     description="Verify user's email address using the code sent to their email",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email", "code"},
     *             @OA\Property(property="email", type="string", format="email", example="user@example.com"),
     *             @OA\Property(property="code", type="string", example="ABC123", description="6-character verification code")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Email verified successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Email has been verified")
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Invalid or expired code",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Invalid or expired verification code")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(
     *                 property="errors",
     *                 type="object",
     *                 @OA\Property(
     *                     property="email",
     *                     type="array",
     *                     @OA\Items(type="string", example="The email field is required.")
     *                 )
     *             )
     *         )
     *     )
     * )
     */
    public function verifyEmail(VerifyEmailRequest $request): JsonResponse
    {
        try {
            $user = User::where('email', $request->email)->first();
            
            $verificationCode = EmailVerificationCode::where('user_id', $user->id)
                ->where('code', $request->code)
                ->where('expires_at', '>', now())
                ->first();

            if (!$verificationCode) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Invalid or expired verification code'
                ], 400);
            }

            if ($user->hasVerifiedEmail()) {
                return response()->json([
                    'status' => 'success',
                    'message' => 'Email already verified'
                ]);
            }

            $user->markEmailAsVerified();
            $verificationCode->delete();

            return response()->json([
                'status' => 'success',
                'message' => 'Email has been verified'
            ]);
        } catch (Exception $e) {
            Log::error('Verify email error: ' . $e->getMessage());
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to verify email',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * @OA\Post(
     *     path="/v1/accounts/email/resend",
     *     tags={"Email Verification"},
     *     summary="Resend verification code (authenticated)",
     *     description="Generate and send a new verification code to authenticated user's email",
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Verification code sent successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Verification code sent")
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Email already verified",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Email already verified")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthenticated",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthenticated.")
     *         )
     *     ),
     *     @OA\Response(
     *         response=429,
     *         description="Too Many Requests",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Too many verification attempts. Please try again later.")
     *         )
     *     )
     * )
     */
    public function resendVerificationEmail(Request $request): JsonResponse
    {
        try {
            $user = Auth::user();

            if ($user->hasVerifiedEmail()) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Email already verified'
                ], 400);
            }

            // Delete any existing codes
            EmailVerificationCode::where('user_id', $user->id)->delete();

            // Generate new code
            $code = strtoupper(Str::random(6));
            
            // Save the code
            EmailVerificationCode::create([
                'user_id' => $user->id,
                'code' => $code,
                'expires_at' => now()->addMinutes(60)
            ]);

            // Send the notification
            $user->notify(new VerifyEmail($code));

            return response()->json([
                'status' => 'success',
                'message' => 'Verification code sent'
            ]);
        } catch (Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to send verification code',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * @OA\Get(
     *     path="/v1/accounts/email/status",
     *     tags={"Email Verification"},
     *     summary="Get email verification status",
     *     description="Check if user's email is verified and if verification code was sent",
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Success",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 @OA\Property(property="email_verified", type="boolean", example=false),
     *                 @OA\Property(property="email", type="string", example="user@example.com"),
     *                 @OA\Property(property="verification_sent", type="boolean", example=true)
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthenticated",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthenticated.")
     *         )
     *     )
     * )
     */
    public function getEmailVerificationStatus(Request $request): JsonResponse
    {
        try {
            $user = Auth::user();
            
            return response()->json([
                'status' => 'success',
                'data' => [
                    'email_verified' => !is_null($user->email_verified_at),
                    'email' => $user->email,
                    'verification_sent' => EmailVerificationCode::where('user_id', $user->id)
                        ->where('expires_at', '>', now())
                        ->exists()
                ]
            ]);
        } catch (Exception $e) {
            Log::error('Get verification status error: ' . $e->getMessage());
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to get verification status',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * @OA\Post(
     *     path="/v1/accounts/email/resend-public",
     *     tags={"Email Verification"},
     *     summary="Resend verification code (public)",
     *     description="Generate and send a new verification code without authentication",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email"},
     *             @OA\Property(property="email", type="string", format="email", example="user@example.com")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Verification code sent successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="A new verification code has been sent to your email")
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Email already verified",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Email is already verified")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(
     *                 property="errors",
     *                 type="object",
     *                 @OA\Property(
     *                     property="email",
     *                     type="array",
     *                     @OA\Items(type="string", example="We could not find a user with that email address.")
     *                 )
     *             )
     *         )
     *     )
     * )
     */
    public function resendVerificationEmailPublic(ResendVerificationRequest $request): JsonResponse
    {
        try {
            $user = User::where('email', $request->email)->first();

            if ($user->hasVerifiedEmail()) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Email is already verified'
                ], 400);
            }

            // Delete any existing codes
            EmailVerificationCode::where('user_id', $user->id)->delete();

            // Generate new code
            $code = strtoupper(Str::random(6));
            
            // Save the code
            EmailVerificationCode::create([
                'user_id' => $user->id,
                'code' => $code,
                'expires_at' => now()->addMinutes(60)
            ]);

            // Send the notification
            $user->notify(new VerifyEmail($code));

            return response()->json([
                'status' => 'success',
                'message' => 'A new verification code has been sent to your email'
            ]);
        } catch (Exception $e) {
            Log::error('Resend verification code error: ' . $e->getMessage());
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to send verification code',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * @OA\Put(
     *     path="/v1/users/{user}",
     *     tags={"User Management"},
     *     summary="Update user role and status (Admin only)",
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="user",
     *         in="path",
     *         description="User ID",
     *         required=true,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"is_admin"},
     *             @OA\Property(property="is_admin", type="boolean", example=false, description="User admin status"),
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="User role updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="User role updated successfully"),
     *             @OA\Property(
     *                 property="data",
     *                 ref="#/components/schemas/User"
     *             )
     *         )
     *     ),
     *     @OA\Response(response=403, description="Unauthorized - Admin access required"),
     *     @OA\Response(response=404, description="User not found")
     * )
     */
    public function updateUser(UpdateUserRequest $request, User $user)
    {
        try {
            // Prevent admin from removing their own admin status
            if ($user->id === auth()->id() && $request->is_admin === false) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'You cannot remove your own admin status'
                ], 403);
            }

            $user->update($request->validated());

            return response()->json([
                'status' => 'success',
                'message' => 'User role updated successfully',
                'data' => $user->fresh()
            ]);

        } catch (\Exception $e) {
            Log::error('User role update error: ' . $e->getMessage());
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to update user role',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * @OA\Put(
     *     path="/v1/accounts/profile",
     *     tags={"Account Management"},
     *     summary="Update user profile",
     *     description="Update authenticated user's profile information",
     *     security={{"bearerAuth":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(property="name", type="string", example="John Doe"),
     *             @OA\Property(property="email", type="string", format="email", example="user@example.com"),
     *             @OA\Property(property="phone", type="string", example="+201234567890")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Profile updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Profile updated successfully"),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 ref="#/components/schemas/User"
     *             )
     *         )
     *     ),
     *     @OA\Response(response=422, description="Validation error"),
     *     @OA\Response(response=401, description="Unauthenticated")
     * )
     */
    public function updateProfile(UpdateProfileRequest $request)
    {
        try {
            $user = auth()->user();
            $data = $request->validated();

            // Update user data
            $updated = $user->update($data);
            Log::info('Update status: ' . ($updated ? 'success' : 'failed'));
            Log::info('Updated user data:', $user->toArray());

            // If email was changed, require re-verification
            if ($user->wasChanged('email')) {
                Log::info('Email was changed, requiring verification');
                $user->email_verified_at = null;
                $user->save();
                
                // Send new verification email
                $user->sendEmailVerificationNotification();

                return response()->json([
                    'status' => 'success',
                    'message' => 'Profile updated successfully. Please verify your new email address.',
                    'data' => $user->fresh(),
                    'email_verification_required' => true
                ]);
            }

            return response()->json([
                'status' => 'success',
                'message' => 'Profile updated successfully',
                'data' => $user->fresh()
            ]);

        } catch (\Exception $e) {
            Log::error('Profile update error: ' . $e->getMessage());
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to update profile',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * @OA\Post(
     *     path="/v1/accounts/avatar",
     *     tags={"Account Management"},
     *     summary="Update user avatar",
     *     description="Upload or update user profile picture. Supports JPG, JPEG, PNG, GIF, BMP, SVG, WEBP formats up to 5MB",
     *     security={{"bearerAuth":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\MediaType(
     *             mediaType="multipart/form-data",
     *             @OA\Schema(
     *                 @OA\Property(
     *                     property="avatar",
     *                     type="string",
     *                     format="binary",
     *                     description="User profile image (jpg, jpeg, png, gif, bmp, svg, webp up to 5MB)"
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Avatar updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Avatar updated successfully"),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 ref="#/components/schemas/User"
     *             )
     *         )
     *     )
     * )
     */
    public function updateAvatar(Request $request)
    {
        try {
            $request->validate([
                'avatar' => 'required|file|image|mimes:jpeg,png,jpg,gif,bmp,svg,webp|max:5120' // 5MB max
            ]);

            $user = Auth::user();

            // Delete old avatar if exists
            if ($user->avatar) {
                Storage::disk('public')->delete($user->avatar);
            }

            // Store new avatar with original extension
            $file = $request->file('avatar');
            $extension = $file->getClientOriginalExtension();
            $avatarPath = $file->storeAs(
                'avatars', 
                'user_' . $user->id . '_' . time() . '.' . $extension, 
                'public'
            );

            $user->update(['avatar' => $avatarPath]);

            return response()->json([
                'status' => 'success',
                'message' => 'Avatar updated successfully',
                'data' => $user->fresh()
            ]);

        } catch (\Exception $e) {
            Log::error('Avatar update error: ' . $e->getMessage());
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to update avatar',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * @OA\Post(
     *     path="/v1/accounts/2fa",
     *     tags={"Account Management"},
     *     summary="Toggle two-factor authentication",
     *     description="Enable or disable two-factor authentication for the user",
     *     security={{"bearerAuth":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"enable"},
     *             @OA\Property(property="enable", type="boolean", example=true)
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="2FA status updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Two-factor authentication has been enabled"),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 ref="#/components/schemas/User"
     *             )
     *         )
     *     )
     * )
     */
    public function toggleTwoFactorAuth(TwoFactorAuthRequest $request)
    {
        try {
            $user = auth()->user();
            $enable = $request->enable;

            $user->update([
                'two_factor_enabled' => $enable,
                // Reset code and expiry when disabling
                'two_factor_code' => $enable ? $user->two_factor_code : null,
                'two_factor_expires_at' => $enable ? $user->two_factor_expires_at : null
            ]);

            return response()->json([
                'status' => 'success',
                'message' => 'Two-factor authentication has been ' . ($enable ? 'enabled' : 'disabled'),
                'data' => $user->fresh()
            ]);

        } catch (\Exception $e) {
            Log::error('2FA toggle error: ' . $e->getMessage());
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to update 2FA status',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * @OA\Post(
     *     path="/v1/accounts/2fa/send-otp",
     *     tags={"Authentication"},
     *     summary="Send OTP for 2FA",
     *     description="Send OTP code to user's email after validating credentials. Required before login if 2FA is enabled.",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email", "password"},
     *             @OA\Property(property="email", type="string", format="email", example="user@example.com"),
     *             @OA\Property(property="password", type="string", format="password", example="password123")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="OTP sent successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="OTP has been sent to your email")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Invalid credentials",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Invalid credentials")
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="2FA not enabled",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="2FA is not enabled for this account")
     *         )
     *     )
     * )
     */
    public function sendOtp(Request $request)
    {
        try {
            $request->validate([
                'email' => 'required|email|exists:users,email',
                'password' => 'required|string'
            ]);

            // Verify credentials first
            if (!Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Invalid credentials'
                ], 401);
            }

            $user = User::where('email', $request->email)->first();

            if (!$user->two_factor_enabled) {
                return response()->json([
                    'status' => 'error',
                    'message' => '2FA is not enabled for this account'
                ], 400);
            }

            // Generate new code
            $code = strtoupper(Str::random(6));
            
            // Save code
            $user->update([
                'two_factor_code' => $code,
                'two_factor_expires_at' => now()->addMinutes(10)
            ]);

            // Send email with code
            Mail::to($user)->send(new TwoFactorCodeMail($code));

            return response()->json([
                'status' => 'success',
                'message' => 'OTP has been sent to your email'
            ]);

        } catch (\Exception $e) {
            Log::error('Send OTP error: ' . $e->getMessage());
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to send OTP'
            ], 500);
        }
    }
}