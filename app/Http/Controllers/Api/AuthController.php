<?php

namespace App\Http\Controllers\Api;

use App\Actions\CreateUserAction;
use App\Http\Controllers\Controller;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Models\User;
use Illuminate\Auth\Events\Registered;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(RegisterRequest $request, CreateUserAction $createUserAction)
    {
        $user = $createUserAction->execute($request->validated());

        event(new Registered($user));

        return response()->json([
            'message' => 'Verification email has been sent.',
            'token' => $user->createToken('token_name')->plainTextToken
        ], 201);
    }

    public function login(LoginRequest $request)
    {
        $user = User::where('email', $request->email)->first();

        abort_if(!$user || !Hash::check($request->password, $user->password), 403);

        return response()->json([
            'token' => $user->createToken('token_name')->plainTextToken,
        ]);
    }
}
