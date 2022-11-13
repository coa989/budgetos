<?php

namespace App\Http\Controllers\Api;

use App\Actions\CreateUserAction;
use App\Http\Controllers\Controller;
use App\Http\Requests\ForgotPasswordRequest;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Http\Requests\ResetPasswordRequest;
use App\Models\User;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Events\Verified;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

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

    public function forgotPassword(ForgotPasswordRequest $request)
    {
        $status = Password::sendResetLink(
            $request->validated()
        );

        if ($status === Password::RESET_LINK_SENT) {
            return response()->json(['message' => __($status)], 200);
        } else {
            throw ValidationException::withMessages([
                'email' => __($status)
            ]);
        }
    }

    public function resetPassword(ResetPasswordRequest $request)
    {
        $status = Password::reset(
            $request->only('email', 'password', 'password_confirmation', 'token'),
            function ($user, $password) {
                $user->forceFill([
                    'password' => Hash::make($password)
                ])->setRememberToken(Str::random(60));

                $user->save();

                event(new PasswordReset($user));
            }
        );

        if ($status == Password::PASSWORD_RESET) {
            return response()->json(['message' => __($status)], 200);
        } else {
            throw ValidationException::withMessages([
                'email' => __($status)
            ]);
        }
    }
}
