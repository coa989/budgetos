<?php

namespace App\Http\Controllers\Api;

use App\Actions\CreateUserAction;
use App\Http\Controllers\Controller;
use App\Http\Requests\CreateAccountRequest;
use App\Http\Requests\RegisterRequest;
use App\Models\Account;
use Illuminate\Http\JsonResponse;

class AccountController extends Controller
{
    /**
     * @OA\Post(
     *      path="/api/accounts",
     *      tags={"Account"},
     *      summary="Create new account",
     *      operationId="create-account",
     *      @OA\RequestBody(
     *          required=true,
     *          description="Pass account details",
     *          @OA\JsonContent(
     *              required={"type", "currency"},
     *              @OA\Property(property="type", type="string", format="text", example="cash"),
     *              @OA\Property(property="currency", type="string", format="text", example="usd"),
     *              @OA\Property(property="balance", type="integer", format="integer", example="10000"),
     *          ),
     *      ),
     *      @OA\Response(response=201, description="Success", @OA\JsonContent()),
     *      @OA\Response(response=422, description="Parameter(s) missing", @OA\JsonContent()),
     * )
     * @param RegisterRequest $request
     * @param CreateUserAction $createUserAction
     * @return JsonResponse
     */
    public function create(CreateAccountRequest $request)
    {
        $account = Account::create(
            array_merge(
                ['user_id' => $request->user()->id],
                $request->validated()
            )
        );

        return response()->json($account, 201);
    }
}
