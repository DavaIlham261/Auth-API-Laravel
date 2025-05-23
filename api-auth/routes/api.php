<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;

// Public routes
Route::get( '/', function (Request $request) {
    return response()->json([
        'status' => true,
        'message' => 'API Auth Service',
        'data' => [
            'version' => '1.0.0',
            'author' => 'Your Name'
        ]
    ]);
});
Route::post( '/register', [AuthController::class, 'register']);
Route::post( '/login', [AuthController::class, 'login']);

// Protected routes
Route::middleware(['auth:sanctum'])->group(function () {
    Route::get( '/user', [AuthController::class, 'user']);
    Route::post( '/logout', [AuthController::class, 'logout']);
});