<!DOCTYPE html>
<html>
<head>
    <title>Verify Your Email Address</title>
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
            background-color: #4CAF50;
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
        .verification-code {
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
        <h2>Verify Your Email Address</h2>
        <p>Hello!</p>
        <p>Thank you for registering with {{ config('app.name') }}. Your verification code is:</p>
        
        <div class="verification-code">
            {{ $verificationCode }}
        </div>
        
        <p>Enter this code in the app to verify your email address.</p>
        <p>If you did not create an account, no further action is required.</p>
        
        <div class="footer">
            <p>This verification code will expire in 60 minutes.</p>
            <p>© {{ date('Y') }} {{ config('app.name') }}. All rights reserved.</p>
        </div>
    </div>
</body>
</html> 