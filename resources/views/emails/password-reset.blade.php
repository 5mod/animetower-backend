<!DOCTYPE html>
<html>
<head>
    <title>Reset Your Password</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background-color: #2148c8;
            color: white;
            padding: 20px;
            text-align: center;
            border-radius: 5px 5px 0 0;
        }
        .content {
            background-color: #f9f9f9;
            padding: 20px;
            border-radius: 0 0 5px 5px;
        }
        .reset-code {
            font-size: 32px;
            letter-spacing: 5px;
            text-align: center;
            padding: 20px;
            background: #e9e9e9;
            border-radius: 4px;
            margin: 20px 0;
        }
        .footer {
            margin-top: 20px;
            text-align: center;
            font-size: 12px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ config('app.name') }}</h1>
    </div>
    
    <div class="content">
        <h2>Reset Your Password</h2>
        <p>Hello!</p>
        <p>You are receiving this email because we received a password reset request for your account.</p>
        
        <p>Your password reset code is:</p>
        <div class="reset-code">
            {{ $code }}
        </div>
        
        <p>This password reset code will expire in 60 minutes.</p>
        <p>If you did not request a password reset, no further action is required.</p>
        
        <div class="footer">
            <p>© {{ date('Y') }} {{ config('app.name') }}. All rights reserved.</p>
        </div>
    </div>
</body>
</html> 