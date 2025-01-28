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
 * @OA\Info(
 *     version="1.0.0",
 *     title="AnimeTower API Documentation",
 *     description="API documentation for AnimeTower application"
 * )
 */

/**
 * @OA\Tag(
 *     name="Authentication",
 *     description="API Endpoints for user authentication",
 *     @OA\ExternalDocumentation(
 *         description="Learn more about authentication",
 *         url="https://laravel.com/docs/11.x/authentication"
 *     )
 * )
 * 
 * @OA\Tag(
 *     name="Two-Factor Authentication",
 *     description="API Endpoints for 2FA management"
 * )
 * 
 * @OA\Tag(
 *     name="Email Verification",
 *     description="API Endpoints for email verification"
 * )
 * 
 * @OA\Tag(
 *     name="Password Management",
 *     description="API Endpoints for password management"
 * )
 * 
 * @OA\Tag(
 *     name="User Management",
 *     description="API Endpoints for user management"
 * )
 * 
 * @OA\Tag(
 *     name="Account Management",
 *     description="API Endpoints for account settings and profile"
 * )
 * 
 * @OA\Tag(
 *     name="Genres",
 *     description="API Endpoints for genre management"
 * )
 * 
 * @OA\Tag(
 *     name="Anime",
 *     description="API Endpoints for anime management"
 * )
 */

class AuthController extends Controller
{
    /**
     * @OA\Post(
     *     path="/v1/accounts/login",
     *     tags={"Authentication"},
     *     summary="Login user and get token",
     *     description="Authenticates user credentials and returns access token. Process varies based on account status:
     *     - If email not verified: Returns error and sends verification code
     *     - If 2FA enabled: First attempt sends OTP, second attempt requires OTP code
     *     - If all verified: Returns access token immediately",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email","password"},
     *             @OA\Property(
     *                 property="email",
     *                 type="string",
     *                 format="email",
     *                 example="user@example.com",
     *                 description="User's registered email address"
     *             ),
     *             @OA\Property(
     *                 property="password",
     *                 type="string",
     *                 format="password",
     *                 example="password123",
     *                 description="User's password"
     *             ),
     *             @OA\Property(
     *                 property="two_factor_code",
     *                 type="string",
     *                 example="QPZ23R",
     *                 description="Required only if 2FA is enabled. Get code from /2fa/send-otp endpoint",
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
     *                     @OA\Property(property="email", type="string", format="email", example="user@example.com"),
     *                     @OA\Property(property="phone", type="string", example="+967777777777"),
     *                     @OA\Property(property="email_verified_at", type="string", format="date-time"),
     *                     @OA\Property(property="is_admin", type="boolean", example=false),
     *                     @OA\Property(property="two_factor_enabled", type="boolean", example=true),
     *                     @OA\Property(property="created_at", type="string", format="date-time"),
     *                     @OA\Property(property="updated_at", type="string", format="date-time")
     *                 ),
     *                 @OA\Property(property="token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1..."),
     *                 @OA\Property(property="refresh_token", type="string", example="def502..."),
     *                 @OA\Property(property="token_type", type="string", example="Bearer")
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Authentication failed",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="The provided credentials are incorrect.")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Additional verification required",
     *         @OA\JsonContent(
     *             oneOf={
     *                 @OA\Schema(
     *                     @OA\Property(property="status", type="string", example="error"),
     *                     @OA\Property(property="message", type="string", example="Email not verified. A new verification code has been sent to your email."),
     *                     @OA\Property(property="verification_required", type="boolean", example=true),
     *                     @OA\Property(property="email", type="string", format="email", example="user@example.com")
     *                 ),
     *                 @OA\Schema(
     *                     @OA\Property(property="status", type="string", example="error"),
     *                     @OA\Property(property="message", type="string", example="Two-factor authentication code is required. Please check your email."),
     *                     @OA\Property(property="requires_2fa", type="boolean", example=true)
     *                 )
     *             }
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
     *     description="Creates a new user account and sends email verification code. The user must verify their email before being able to login.",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"name","email","phone","password","password_confirmation"},
     *             @OA\Property(
     *                 property="name",
     *                 type="string",
     *                 example="Test User",
     *                 description="User's full name"
     *             ),
     *             @OA\Property(
     *                 property="email",
     *                 type="string",
     *                 format="email",
     *                 example="user@example.com",
     *                 description="User's email address (must be unique)"
     *             ),
     *             @OA\Property(
     *                 property="phone",
     *                 type="string",
     *                 example="+967777777777",
     *                 description="User's phone number"
     *             ),
     *             @OA\Property(
     *                 property="password",
     *                 type="string",
     *                 format="password",
     *                 example="password123",
     *                 description="Password (min 8 characters)"
     *             ),
     *             @OA\Property(
     *                 property="password_confirmation",
     *                 type="string",
     *                 format="password",
     *                 example="password123",
     *                 description="Must match password field"
     *             )
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
     *                 @OA\Property(
     *                     property="user",
     *                     type="object",
     *                     @OA\Property(property="id", type="integer", example=1),
     *                     @OA\Property(property="name", type="string", example="John Doe"),
     *                     @OA\Property(property="email", type="string", format="email", example="user@example.com"),
     *                     @OA\Property(property="phone", type="string", example="+967777777777"),
     *                     @OA\Property(property="created_at", type="string", format="date-time"),
     *                     @OA\Property(property="updated_at", type="string", format="date-time")
     *                 )
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
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             oneOf={
     *                 @OA\Schema(
     *                     @OA\Property(property="status", type="string", example="error"),
     *                     @OA\Property(property="message", type="string", example="Failed to create user account. Please try again.")
     *                 ),
     *                 @OA\Schema(
     *                     @OA\Property(property="status", type="string", example="error"),
     *                     @OA\Property(property="message", type="string", example="Account created but failed to send verification email. Please request a new verification code.")
     *                 )
     *             }
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
     * @OA\Post(
     *     path="/v1/accounts/logout",
     *     tags={"Authentication"},
     *     summary="Logout user",
     *     description="Revoke the current access and refresh tokens",
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
     *         description="Unauthorized or Invalid token",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="User not authenticated")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Failed to revoke authentication tokens")
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
                    'message' => 'User not authenticated'
                ], 401);
            }

            try {
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

                Log::info('User logged out successfully: ' . $user->id);

                return response()->json([
                    'status' => 'success',
                    'message' => 'Successfully logged out'
                ]);

            } catch (\Exception $e) {
                Log::error('Token revocation error: ' . $e->getMessage());
                return response()->json([
                    'status' => 'error',
                    'message' => 'Failed to revoke authentication tokens'
                ], 500);
            }

        } catch (\Exception $e) {
            Log::error('Logout error: ' . $e->getMessage());
            return response()->json([
                'status' => 'error',
                'message' => 'An unexpected error occurred during logout'
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
     *                 @OA\Property(property="user", ref="#/components/schemas/User")
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="User not authenticated",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="User not authenticated")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Failed to retrieve user data")
     *         )
     *     )
     * )
     */
    public function getUser(): JsonResponse
    {
        try {
            $user = Auth::user();

            if (!$user) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'User not authenticated'
                ], 401);
            }

            Log::info('User data retrieved successfully: ' . $user->id);

            return response()->json([
                'status' => 'success',
                'data' => [
                    'user' => $user
                ]
            ]);

        } catch (\Exception $e) {
            Log::error('Get user error: ' . $e->getMessage());
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to retrieve user data'
            ], 500);
        }
    }

    /**
     * @OA\Post(
     *     path="/v1/accounts/token/refresh",
     *     tags={"Authentication"},
     *     summary="Refresh access token",
     *     description="Get a new access token using refresh token. The old tokens will be revoked.",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"refresh_token"},
     *             @OA\Property(
     *                 property="refresh_token",
     *                 type="string",
     *                 example="def502...",
     *                 description="The refresh token received during login"
     *             )
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
     *                 @OA\Property(property="refresh_token", type="string", example="def502..."),
     *                 @OA\Property(property="token_type", type="string", example="Bearer")
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Invalid token",
     *         @OA\JsonContent(
     *             oneOf={
     *                 @OA\Schema(
     *                     @OA\Property(property="status", type="string", example="error"),
     *                     @OA\Property(property="message", type="string", example="Invalid refresh token")
     *                 ),
     *                 @OA\Schema(
     *                     @OA\Property(property="status", type="string", example="error"),
     *                     @OA\Property(property="message", type="string", example="Invalid access token")
     *                 )
     *             }
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
     *             @OA\Property(property="message", type="string", example="Failed to refresh token")
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
                    'refresh_token' => $refreshToken,
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
     *     summary="Request password reset",
     *     description="Send a password reset code to user's email. The code expires after 60 minutes.",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email"},
     *             @OA\Property(
     *                 property="email",
     *                 type="string",
     *                 format="email",
     *                 example="user@example.com",
     *                 description="Email address of the account to reset"
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Reset code sent successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Password reset code has been sent to your email")
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="User not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="No user found with this email address")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(
     *                 property="message",
     *                 type="object",
     *                 @OA\Property(
     *                     property="email",
     *                     type="array",
     *                     @OA\Items(type="string", example="The email field is required.")
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Failed to process password reset request")
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
                'message' => 'Password reset code has been sent to your email'
            ]);
        } catch (Exception $e) {
            Log::error('Forgot password error: ' . $e->getMessage());
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to process password reset request',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * @OA\Post(
     *     path="/v1/accounts/password/reset",
     *     tags={"Password Management"},
     *     summary="Reset password using code",
     *     description="Reset user's password using the code sent to their email. The code must be valid and not expired. 
     *     After successful reset, all existing tokens will be revoked.",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email", "code", "password", "password_confirmation"},
     *             @OA\Property(
     *                 property="email",
     *                 type="string",
     *                 format="email",
     *                 example="user@example.com",
     *                 description="Email address of the account"
     *             ),
     *             @OA\Property(
     *                 property="code",
     *                 type="string",
     *                 example="ABC123",
     *                 description="6-character reset code received via email"
     *             ),
     *             @OA\Property(
     *                 property="password",
     *                 type="string",
     *                 format="password",
     *                 example="newpassword123",
     *                 description="New password (min 8 characters)"
     *             ),
     *             @OA\Property(
     *                 property="password_confirmation",
     *                 type="string",
     *                 format="password",
     *                 example="newpassword123",
     *                 description="Must match new password"
     *             )
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
     *         description="Reset error",
     *         @OA\JsonContent(
     *             oneOf={
     *                 @OA\Schema(
     *                     @OA\Property(property="status", type="string", example="error"),
     *                     @OA\Property(property="message", type="string", example="Invalid reset code")
     *                 ),
     *                 @OA\Schema(
     *                     @OA\Property(property="status", type="string", example="error"),
     *                     @OA\Property(property="message", type="string", example="Reset code has expired")
     *                 )
     *             }
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="User not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="No user found with this email address")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(
     *                 property="message",
     *                 type="object",
     *                 @OA\Property(property="email", type="array", @OA\Items(type="string", example="The email field is required.")),
     *                 @OA\Property(property="code", type="array", @OA\Items(type="string", example="The code field is required.")),
     *                 @OA\Property(property="password", type="array", @OA\Items(type="string", example="The password must be at least 8 characters."))
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Failed to reset password")
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
     *     summary="Change user password",
     *     description="Change password for authenticated user. All existing tokens will be revoked, requiring re-login. 
     *     A notification will be sent to user's email.",
     *     security={{"bearerAuth":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"current_password", "password", "password_confirmation"},
     *             @OA\Property(
     *                 property="current_password",
     *                 type="string",
     *                 format="password",
     *                 example="oldpassword123",
     *                 description="User's current password"
     *             ),
     *             @OA\Property(
     *                 property="password",
     *                 type="string",
     *                 format="password",
     *                 example="newpassword123",
     *                 description="New password (min 8 characters, must be different from current)"
     *             ),
     *             @OA\Property(
     *                 property="password_confirmation",
     *                 type="string",
     *                 format="password",
     *                 example="newpassword123",
     *                 description="Must match new password"
     *             )
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
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Unauthenticated")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(
     *                 property="message",
     *                 type="object",
     *                 @OA\Property(
     *                     property="current_password",
     *                     type="array",
     *                     @OA\Items(type="string", example="The current password is incorrect.")
     *                 ),
     *                 @OA\Property(
     *                     property="password",
     *                     type="array",
     *                     @OA\Items(type="string", example="The password must be at least 8 characters.")
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Failed to change password")
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
     *     summary="Verify email address",
     *     description="Verify user's email address using the verification code sent to their email. 
     *     The code expires after 60 minutes.",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email", "code"},
     *             @OA\Property(
     *                 property="email",
     *                 type="string",
     *                 format="email",
     *                 example="user@example.com",
     *                 description="Email address to verify"
     *             ),
     *             @OA\Property(
     *                 property="code",
     *                 type="string",
     *                 example="ABC123",
     *                 description="6-character verification code received via email"
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Email verified successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Email verified successfully"),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 ref="#/components/schemas/User"
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Verification error",
     *         @OA\JsonContent(
     *             oneOf={
     *                 @OA\Schema(
     *                     @OA\Property(property="status", type="string", example="error"),
     *                     @OA\Property(property="message", type="string", example="Invalid verification code")
     *                 ),
     *                 @OA\Schema(
     *                     @OA\Property(property="status", type="string", example="error"),
     *                     @OA\Property(property="message", type="string", example="Verification code has expired")
     *                 ),
     *                 @OA\Schema(
     *                     @OA\Property(property="status", type="string", example="error"),
     *                     @OA\Property(property="message", type="string", example="Email is already verified")
     *                 )
     *             }
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
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(
     *                 property="message",
     *                 type="object",
     *                 @OA\Property(property="email", type="array", @OA\Items(type="string", example="The email field is required.")),
     *                 @OA\Property(property="code", type="array", @OA\Items(type="string", example="The code field is required."))
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
     *     summary="Resend verification email",
     *     description="Send a new verification code to authenticated user's email. Previous code will be invalidated. 
     *     Limited to 6 requests per minute.",
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Verification email sent successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="A new verification code has been sent to your email")
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Verification error",
     *         @OA\JsonContent(
     *             oneOf={
     *                 @OA\Schema(
     *                     @OA\Property(property="status", type="string", example="error"),
     *                     @OA\Property(property="message", type="string", example="Email is already verified")
     *                 ),
     *                 @OA\Schema(
     *                     @OA\Property(property="status", type="string", example="error"),
     *                     @OA\Property(property="message", type="string", example="Previous verification code is still valid")
     *                 )
     *             }
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Unauthenticated")
     *         )
     *     ),
     *     @OA\Response(
     *         response=429,
     *         description="Too Many Requests",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Too many verification requests. Please try again later.")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Failed to send verification code")
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
                'message' => 'Verification email sent'
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
     *     description="Check if user's email is verified and if a verification code is currently active. 
     *     Used to determine if user needs to verify email or request a new code.",
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Status retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 @OA\Property(
     *                     property="email_verified",
     *                     type="boolean",
     *                     example=false,
     *                     description="Whether the email is verified"
     *                 ),
     *                 @OA\Property(
     *                     property="email",
     *                     type="string",
     *                     format="email",
     *                     example="user@example.com",
     *                     description="User's email address"
     *                 ),
     *                 @OA\Property(
     *                     property="verification_sent",
     *                     type="boolean",
     *                     example=true,
     *                     description="Whether there is an active verification code"
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Unauthenticated")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Failed to get verification status")
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
     *     summary="Resend verification email (public)",
     *     description="Send a new verification code to user's email without requiring authentication. 
     *     Previous code will be invalidated. Limited to 6 requests per minute.",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email"},
     *             @OA\Property(
     *                 property="email",
     *                 type="string",
     *                 format="email",
     *                 example="user@example.com",
     *                 description="Email address to send verification code"
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Verification email sent successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="A new verification code has been sent to your email")
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Verification error",
     *         @OA\JsonContent(
     *             oneOf={
     *                 @OA\Schema(
     *                     @OA\Property(property="status", type="string", example="error"),
     *                     @OA\Property(property="message", type="string", example="Email is already verified")
     *                 ),
     *                 @OA\Schema(
     *                     @OA\Property(property="status", type="string", example="error"),
     *                     @OA\Property(property="message", type="string", example="Previous verification code is still valid")
     *                 )
     *             }
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="User not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="No user found with this email address")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(
     *                 property="message",
     *                 type="object",
     *                 @OA\Property(property="email", type="array", @OA\Items(type="string", example="The email field is required."))
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=429,
     *         description="Too Many Requests",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Too many verification requests. Please try again later.")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Failed to send verification code")
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
     *     description="Update user's admin status. Admin cannot remove their own admin status.",
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="user",
     *         in="path",
     *         description="ID of user to update",
     *         required=true,
     *         @OA\Schema(type="integer", format="int64")
     *     ),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"is_admin"},
     *             @OA\Property(
     *                 property="is_admin",
     *                 type="boolean",
     *                 example=false,
     *                 description="Set user's admin status"
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="User updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="User role updated successfully"),
     *             @OA\Property(property="data", ref="#/components/schemas/User")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Unauthenticated")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden",
     *         @OA\JsonContent(
     *             oneOf={
     *                 @OA\Schema(
     *                     @OA\Property(property="status", type="string", example="error"),
     *                     @OA\Property(property="message", type="string", example="Admin access required")
     *                 ),
     *                 @OA\Schema(
     *                     @OA\Property(property="status", type="string", example="error"),
     *                     @OA\Property(property="message", type="string", example="You cannot remove your own admin status")
     *                 )
     *             }
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
     *             @OA\Property(property="message", type="string", example="Failed to update user role")
     *         )
     *     )
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
     *     description="Update authenticated user's profile information. If email is changed, verification will be required.",
     *     security={{"bearerAuth":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(
     *                 property="name",
     *                 type="string",
     *                 example="Test User",
     *                 description="User's full name"
     *             ),
     *             @OA\Property(
     *                 property="email",
     *                 type="string",
     *                 format="email",
     *                 example="user@example.com",
     *                 description="User's email address. Changing email requires verification."
     *             ),
     *             @OA\Property(
     *                 property="phone",
     *                 type="string",
     *                 example="+967777777777",
     *                 description="User's phone number"
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Profile updated successfully",
     *         @OA\JsonContent(
     *             oneOf={
     *                 @OA\Schema(
     *                     @OA\Property(property="status", type="string", example="success"),
     *                     @OA\Property(property="message", type="string", example="Profile updated successfully"),
     *                     @OA\Property(property="data", ref="#/components/schemas/User")
     *                 ),
     *                 @OA\Schema(
     *                     @OA\Property(property="status", type="string", example="success"),
     *                     @OA\Property(property="message", type="string", example="Profile updated successfully. Please verify your new email address."),
     *                     @OA\Property(property="data", ref="#/components/schemas/User"),
     *                     @OA\Property(property="email_verification_required", type="boolean", example=true)
     *                 )
     *             }
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Unauthenticated")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(
     *                 property="message",
     *                 type="object",
     *                 @OA\Property(property="email", type="array", @OA\Items(type="string", example="The email has already been taken.")),
     *                 @OA\Property(property="phone", type="array", @OA\Items(type="string", example="The phone field is required."))
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Failed to update profile")
     *         )
     *     )
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
     *     description="Upload or update user profile picture. Previous avatar will be deleted if it exists. 
     *     Supports JPG, JPEG, PNG, GIF, BMP, SVG, WEBP formats up to 5MB.",
     *     security={{"bearerAuth":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\MediaType(
     *             mediaType="multipart/form-data",
     *             @OA\Schema(
     *                 required={"avatar"},
     *                 @OA\Property(
     *                     property="avatar",
     *                     type="string",
     *                     format="binary",
     *                     description="Image file (max 5MB). Allowed types: jpg, jpeg, png, gif, bmp, svg, webp"
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
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Unauthenticated")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(
     *                 property="message",
     *                 type="object",
     *                 @OA\Property(
     *                     property="avatar",
     *                     type="array",
     *                     @OA\Items(
     *                         type="string",
     *                         example="The avatar field is required."
     *                     )
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Failed to update avatar")
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
     *     tags={"Two-Factor Authentication"},
     *     summary="Toggle two-factor authentication",
     *     description="Enable or disable two-factor authentication for the authenticated user. When enabled, login will require an OTP code.",
     *     security={{"bearerAuth":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"enable"},
     *             @OA\Property(
     *                 property="enable",
     *                 type="boolean",
     *                 example=true,
     *                 description="True to enable 2FA, false to disable it"
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="2FA status updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(
     *                 property="message",
     *                 type="string",
     *                 example="Two-factor authentication has been enabled",
     *                 description="Message will indicate whether 2FA was enabled or disabled"
     *             ),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 ref="#/components/schemas/User"
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Unauthenticated")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(
     *                 property="message",
     *                 type="object",
     *                 @OA\Property(
     *                     property="enable",
     *                     type="array",
     *                     @OA\Items(type="string", example="The enable field is required.")
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Failed to update 2FA status")
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
     *     tags={"Two-Factor Authentication"},
     *     summary="Send OTP code for 2FA",
     *     description="Validates user credentials and sends a one-time password to the user's email for two-factor authentication. 
     *     The OTP code expires in 10 minutes.",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email", "password"},
     *             @OA\Property(
     *                 property="email",
     *                 type="string",
     *                 format="email",
     *                 example="user@example.com",
     *                 description="User's registered email address"
     *             ),
     *             @OA\Property(
     *                 property="password",
     *                 type="string",
     *                 format="password",
     *                 example="password123",
     *                 description="User's password"
     *             )
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
     *         response=400,
     *         description="2FA not enabled",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="2FA is not enabled for this account")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Authentication failed",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Invalid credentials")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(
     *                 property="message",
     *                 type="object",
     *                 @OA\Property(property="email", type="array", @OA\Items(type="string", example="The email field is required.")),
     *                 @OA\Property(property="password", type="array", @OA\Items(type="string", example="The password field is required."))
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Failed to send OTP")
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