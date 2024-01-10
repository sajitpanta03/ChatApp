<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegistrationRequest;
use App\Models\User;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function __contruct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    public function register(RegistrationRequest $registrationRequest)
    {
        $validated = $registrationRequest->validated();

        if (!$validated) {
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $registrationRequest->errors()
            ], 422);
        }

        $user = User::create([
            'name' => $registrationRequest->name,
            'email' => $registrationRequest->email,
            'password' => Hash::make($registrationRequest->password),
        ]);

        return response()->json([
            'message' => 'User created successfully',
            'user' => $user
        ]);
    }

    public function login(LoginRequest $loginRequest)
    {
        $credentials = $loginRequest->validated();

        if (auth()->attempt($credentials)) {
            $user = auth()->user();
            $user['token'] = $user->createToken('API Token')->accessToken;

            return response()->json([
                'user' => $user
            ], 200);
        }
        return response()->json([
            'message' => 'Invalid credentials'
        ], 401);
    }

    public function logout()
    {
        auth()->user()->tokens()->delete();
        return response()->json([
            'message' => 'Successfully logged out'
        ]);
    }
}
