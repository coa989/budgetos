<?php

namespace App\Http\Controllers\Api;

use App\Actions\CreateUserAction;
use App\Domains\Authentication\Http\Requests\EmailVerificationRequest;
use App\Http\Controllers\Controller;
use App\Http\Requests\ForgotPasswordRequest;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Http\Requests\ResetPasswordRequest;
use App\Models\User;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Events\Verified;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    /**
     * @OA\Post(
     *      path="/api/auth/register",
     *      tags={"Authentication"},
     *      summary="Register new user and gain access token.",
     *      operationId="register",
     *      @OA\RequestBody(
     *          required=true,
     *          description="Pass user details",
     *          @OA\JsonContent(
     *              required={"username", "email","password", "password_confirmation"},
     *              @OA\Property(property="name", type="string", format="text", example="SomeFancyUsername"),
     *              @OA\Property(property="email", type="string", format="email", example="vladimir.vulovic@quantox.com"),
     *              @OA\Property(property="password", type="string", format="password", example="password"),
     *              @OA\Property(property="password_confirmation", type="string", format="password", example="password"),
     *          ),
     *      ),
     *      @OA\Response(response=200, description="Success", @OA\JsonContent()),
     *      @OA\Response(response=422, description="Parameter(s) missing", @OA\JsonContent()),
     * )
     * @param RegisterRequest $request
     * @param CreateUserAction $createUserAction
     * @return JsonResponse
     */
    public function register(RegisterRequest $request, CreateUserAction $createUserAction): JsonResponse
    {
        $user = $createUserAction->execute($request->validated());

        event(new Registered($user));

        return response()->json([
            'message' => 'Verification email has been sent.',
            'access_token' => $user->createToken('token_name')->plainTextToken
        ], 201);
    }

    /**
     * @OA\Post(
     *      path="/api/auth/login",
     *      tags={"Authentication"},
     *      summary="Authenticate using user credentials to gain access token.",
     *      operationId="login",
     *      @OA\RequestBody(
     *          required=true,
     *          description="Pass user credentials",
     *          @OA\JsonContent(
     *              required={"email","password"},
     *              @OA\Property(property="email", type="string", example="member@quantox.com"),
     *              @OA\Property(property="password", type="string", format="password", example="password"),
     *          ),
     *      ),
     *      @OA\Response(response=200, description="Success", @OA\JsonContent()),
     *      @OA\Response(response=400, description="Bad request", @OA\JsonContent()),
     *      @OA\Response(response=422, description="Parameter(s) missing", @OA\JsonContent()),
     * )
     * @param LoginRequest $request
     * @return JsonResponse
     */
    public function login(LoginRequest $request): JsonResponse
    {
        $user = User::where('email', $request->email)->first();

        abort_if(!$user || !Hash::check($request->password, $user->password), 400);

        return response()->json([
            'access_token' => $user->createToken('token_name')->plainTextToken,
        ]);
    }

    /**
     * @OA\Post(
     *      path="/api/auth/logout",
     *      tags={"Authentication"},
     *      summary="Logout user.",
     *      operationId="logout",
     *      @OA\Response(response=204, description="Success", @OA\JsonContent()),
     *      @OA\Response(response=401, description="Unauthorized", @OA\JsonContent()),
     *      security={
     *          {"bearer_token": {}}
     *      }
     * )
     */
    public function logout()
    {
        Auth::user()->tokens()->delete();

        return response()->noContent();
    }

    /**
     * @OA\Get(
     *      path="/api/auth/email/verify/{id}/{hash}",
     *      tags={"Authentication"},
     *      summary="Verify account using signed URL received via email.",
     *      operationId="verify",
     *      @OA\Parameter(name="id", in="path", example="1"),
     *      @OA\Parameter(name="hash", in="path", example="d48d03a1cfe1859b9cde06a6ecfdf17640bc930e"),
     *      @OA\Parameter(name="expires", in="query", example="1633336613"),
     *      @OA\Parameter(name="signature", in="query", example="7cf9ca062d99f230b557bd6c6d8db2ed2ee830a962423db5cead7e0e119a200c"),
     *
     *      @OA\Response(response=200, description="Success", @OA\JsonContent()),
     *      @OA\Response(response=400, description="Bad request", @OA\JsonContent()),
     *      @OA\Response(response=404, description="Not found", @OA\JsonContent()),
     *      @OA\Response(response=401, description="Unauthorized", @OA\JsonContent()),
     * )
     * @param Request $request
     * @return JsonResponse
     */
    public function verifyEmail(Request $request): JsonResponse
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

    /**
     * @OA\Post(
     *      path="/api/auth/forgot-password",
     *      tags={"Authentication"},
     *      summary="Send forgot password email",
     *      operationId="forgot-password",
     *     @OA\RequestBody(
     *          required=true,
     *          description="Pass user email",
     *          @OA\JsonContent(
     *              required={"email"},
     *              @OA\Property(property="email", type="string", example="member@quantox.com"),
     *          ),
     *      ),
     *      @OA\Response(response=200, description="Success", @OA\JsonContent()),
     *      @OA\Response(response=422, description="Parameter(s) missing", @OA\JsonContent()),
     * )
     */
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

    /**
     * @OA\Post(
     *      path="/api/auth/reset-password",
     *      tags={"Authentication"},
     *      summary="Reset user password",
     *      operationId="reset-password",
     *     @OA\RequestBody(
     *          required=true,
     *          description="Pass user email, password and token from forgot password email",
     *          @OA\JsonContent(
     *              required={"email", "token", "password"},
     *              @OA\Property(property="email", type="string", example="member@quantox.com"),
     *              @OA\Property(property="password", type="string", format="password", example="password"),
     *              @OA\Property(property="token", type="string", example="11c480d6bf0940803c6853cd6c7bb1f57371794500f53eae216721b19aa40864"),
     *          ),
     *      ),
     *      @OA\Response(response=200, description="Success", @OA\JsonContent()),
     *      @OA\Response(response=422, description="Parameter(s) missing", @OA\JsonContent()),
     * )
     */
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

    /**
     * @OA\Post(
     *      path="/api/auth/email/verification-notification",
     *      tags={"Authentication"},
     *      summary="Resend verification URL.",
     *      operationId="resend",
     *      @OA\Response(response=200, description="Success", @OA\JsonContent()),
     *      @OA\Response(response=401, description="Unauthorized", @OA\JsonContent()),
     *      security={
     *          {"bearer_token": {}}
     *      }
     * )
     *
     * @return JsonResponse
     */
    public function resendVerificationEmail(): JsonResponse
    {
        Auth::user()->sendEmailVerificationNotification();

        return response()->json(['message' => 'Email has been sent'], 200);
    }
}
