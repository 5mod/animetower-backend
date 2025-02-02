<?php

use Illuminate\Support\Facades\Route;

// Redirect root to API documentation
Route::get('/', function () {
    return redirect('/api/documentation');
});

// Route::get('/docs', function () {
//     return redirect('/api/documentation');
// });

// Route::get('/welcome', function () {
//     return view('welcome');
// });
