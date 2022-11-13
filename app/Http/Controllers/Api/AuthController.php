<?php

namespace App\Http\Controllers\Api;

use App\Actions\CreateUserAction;
use App\Http\Controllers\Controller;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Models\User;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Events\Verified;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(RegisterRequest $request, CreateUserAction $createUserAction)
    {
        $user = $createUserAction->execute($request->validated());

        event(new Registered($user));

        return response()->json([
            'message' => 'Verification email has been sent.',
            'access_token' => $user->createToken('token_name')->plainTextToken
        ], 201);
    }

    public function login(LoginRequest $request)
    {
        $user = User::where('email', $request->email)->first();

        abort_if(!$user || !Hash::check($request->password, $user->password), 400);

        return response()->json([
            'access_token' => $user->createToken('token_name')->plainTextToken,
        ]);
    }

    public function logout()
    {
        Auth::user()->tokens()->delete();

        return response()->noContent();
    }

    public function verifyEmail(Request $request)
    {
        $user = User::find($request->route('id'));

        if ($user->hasVerifiedEmail()) {
            return response()->json([
                'message' => 'Email is already verified'
            ], 400);
        }

        if ($user->markEmailAsVerified()) {
            event(new Verified($user));
        }

        return response()->json([
            'message' => 'Success'
        ]);
    }
}
