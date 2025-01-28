<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use App\Http\Controllers\Api\GenreController;
use App\Http\Controllers\Api\AnimeController;
use App\Http\Middleware\ForceJsonResponse;
use App\Http\Middleware\IsUserVerified;
use App\Http\Middleware\IsAdmin;
use App\Http\Middleware\IsActive;
// Route::get('/user', function (Request $request) {
//     return $request->user();
// })->middleware('auth:api');

// API v1 Routes
Route::prefix('v1')->group(function () {
    Route::middleware(ForceJsonResponse::class)->group(function () {
    // Public routes
    Route::prefix('accounts')->group(function () {
        Route::post('login', [AuthController::class, 'login']);
        Route::post('register', [AuthController::class, 'register']);
        Route::post('token/refresh', [AuthController::class, 'refreshToken']);
        Route::post('password/forgot', [AuthController::class, 'forgotPassword']);
        Route::post('password/reset', [AuthController::class, 'resetPassword']);
        Route::post('email/verify', [AuthController::class, 'verifyEmail']);
        Route::post('email/resend-public', [AuthController::class, 'resendVerificationEmailPublic']);
        Route::post('2fa/send-otp', [AuthController::class, 'sendOtp']);
    });

    // Public anime & genre routes
    Route::get('anime', [AnimeController::class, 'index']);
    Route::get('anime/{anime}', [AnimeController::class, 'show']);
    Route::get('genres', [GenreController::class, 'index']);
    Route::get('genres/{genre}', [GenreController::class, 'show']);

    // Protected routes
    Route::middleware(['auth:api', IsActive::class, IsUserVerified::class])->group(function () {
        // Account management
        Route::prefix('accounts')->group(function () {
            Route::get('user', [AuthController::class, 'getUser']);
            Route::post('logout', [AuthController::class, 'logout']);
            Route::post('password/change', [AuthController::class, 'changePassword']);
            Route::get('email/status', [AuthController::class, 'getEmailVerificationStatus']);
            Route::post('email/resend', [AuthController::class, 'resendVerificationEmail'])
                    ->middleware('throttle:6,1');
            Route::put('profile', [AuthController::class, 'updateProfile']);
            Route::post('avatar', [AuthController::class, 'updateAvatar']);
            Route::post('2fa', [AuthController::class, 'toggleTwoFactorAuth']);
        });

        // Admin only routes
        Route::middleware([IsAdmin::class])->group(function () {
            // Anime CRUD operations
            Route::post('anime', [AnimeController::class, 'store']);
            Route::put('anime/{anime}', [AnimeController::class, 'update']);
            Route::delete('anime/{anime}', [AnimeController::class, 'destroy']);
            Route::post('anime/{anime}/restore', [AnimeController::class, 'restore']);

            // Genre CRUD operations
            Route::post('genres', [GenreController::class, 'store']);
            Route::put('genres/{genre}', [GenreController::class, 'update']);
            Route::delete('genres/{genre}', [GenreController::class, 'destroy']);
            Route::post('genres/{genre}/restore', [GenreController::class, 'restore']);

            // User management routes
            Route::put('users/{user}', [AuthController::class, 'updateUser']);
        });
    });
    });
});

// Test routes (should be removed in production)
Route::prefix('test')->group(function () {
    Route::get('/auth', function (Request $request) {
        return [
            'token_in_header' => $request->header('Authorization'),
            'user' => auth()->user(),
            'is_authenticated' => auth()->check()
        ];
    })->middleware('auth:api');

    Route::get('/email', function () {
        try {
            Log::info('Attempting to send test email');
            Mail::to('test@example.com')->send(new \App\Mail\TestMail());
            Log::info('Test email sent successfully');
            return response()->json([
                'status' => 'success',
                'message' => 'Test email sent successfully'
            ]);
        } catch (\Exception $e) {
            Log::error('Failed to send test email: ' . $e->getMessage());
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to send test email',
                'error' => $e->getMessage()
            ], 500);
        }
    });
});
