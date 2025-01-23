<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;


Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:api');

Route::post('/v1/account/login', [AuthController::class, 'login']);
Route::post('/v1/account/register', [AuthController::class, 'register']);
Route::post('/v1/account/refresh', [AuthController::class, 'refreshToken']);

Route::group(['middleware' => 'auth:api'], function () {
    Route::get('/v1/account/user', [AuthController::class, 'getUser']);
    Route::get('/v1/account/logout', [AuthController::class, 'refreshToken']);
});
