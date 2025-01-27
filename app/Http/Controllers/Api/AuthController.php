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
     *     description="Authenticate user and return access token. Email must be verified.",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email","password"},
     *             @OA\Property(property="email", type="string", format="email", example="user@example.com"),
     *             @OA\Property(property="password", type="string", format="password", example="password123")
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
     *                     @OA\Property(property="is_admin", type="boolean", example=false)
     *                 ),
     *                 @OA\Property(property="token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1..."),
     *                 @OA\Property(property="token_type", type="string", example="Bearer"),
     *                 @OA\Property(property="email_verified", type="boolean", example=true)
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Invalid credentials",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="The provided credentials are incorrect.")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Email not verified",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Please verify your email address before logging in."),
     *             @OA\Property(property="verification_required", type="boolean", example=true),
     *             @OA\Property(property="email", type="string", example="user@example.com")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="An error occurred while logging in. Please try again.")
     *         )
     *     )
     * )
     */
    public function login(LoginRequest $request): JsonResponse
    {
        try {
            if (!Auth::attempt($request->validated())) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'The provided credentials are incorrect.'
                ], 401);
            }

            $user = Auth::user();

            // Check if email is verified
            if (!$user->hasVerifiedEmail()) {
                // Generate new verification code if needed
                if (!EmailVerificationCode::where('user_id', $user->id)
                    ->where('expires_at', '>', now())
                    ->exists()) {
                    
                    $code = strtoupper(Str::random(6));
                    EmailVerificationCode::updateOrCreate(
                        ['user_id' => $user->id],
                        [
                            'code' => $code,
                            'expires_at' => now()->addMinutes(60)
                        ]
                    );

                    // Send notification using template
                    $user->notify(new VerifyEmail($code));
                }

                return response()->json([
                    'status' => 'error',
                    'message' => 'Please verify your email address before logging in. A new verification code has been sent to your email.',
                    'verification_required' => true,
                    'email' => $user->email
                ], 403);
            }

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
            Log::error('Login error: ' . $e->getMessage());
            Log::error('Stack trace: ' . $e->getTraceAsString());
            return response()->json([
                'status' => 'error',
                'message' => 'An error occurred while logging in. Please try again.'
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
            
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'phone' => $request->phone,
                'password' => Hash::make($request->password),
            ]);
            Log::info('User created with ID: ' . $user->id);

            $token = $user->createToken('auth-token');
            Log::info('Token created');
            
            // Generate verification code
            $code = strtoupper(Str::random(6));
            
            // Save code
            EmailVerificationCode::updateOrCreate(
                ['user_id' => $user->id],
                [
                    'code' => $code,
                    'expires_at' => now()->addMinutes(60)
                ]
            );

            // Send notification using template
            $user->notify(new VerifyEmail($code));
            Log::info('Verification email sent successfully');

            return response()->json([
                'status' => 'success',
                'message' => 'Successfully registered. Please check your email to verify your account.',
                'data' => [
                    'user' => $user,
                    'token' => $token->accessToken,
                    'token_type' => 'Bearer',
                ]
            ], 201);
        } catch (Exception $e) {
            Log::error('Registration error: ' . $e->getMessage());
            Log::error($e->getTraceAsString());
            return response()->json([
                'status' => 'error',
                'message' => 'An error occurred while registering. Please try again.',
                'error' => $e->getMessage()
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
}