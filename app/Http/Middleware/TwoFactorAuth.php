<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use App\Notifications\TwoFactorCode;

class TwoFactorAuth
{
    public function handle(Request $request, Closure $next)
    {
        $user = Auth::user();

        // Skip if 2FA is not enabled
        if (!$user->two_factor_enabled) {
            return $next($request);
        }

        // If this is the verification endpoint and we have a valid code, let them through
        if ($request->is('*/verify-2fa') && $user->two_factor_code) {
            return $next($request);
        }

        // Generate and send new 2FA code
        $code = strtoupper(Str::random(6));
        
        $user->update([
            'two_factor_code' => $code,
            'two_factor_expires_at' => now()->addMinutes(10)
        ]);

        // Send the code via email
        $user->notify(new TwoFactorCode($code));

        return response()->json([
            'status' => 'pending',
            'message' => 'Please verify your login with the code sent to your email.',
            'requires_2fa' => true
        ], 403);
    }
} 