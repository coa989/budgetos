<?php

namespace App\Actions;

use App\Models\User;
use Illuminate\Support\Facades\Hash;

class CreateUserAction
{
    /**
     * @param array $data
     * @return User
     */
    public function execute(array $data): User
    {
        return User::create([
            'name'     =>  $data['name'],
            'email'    => $data['email'],
            'password' => Hash::make($data['password'])
        ]);
    }
}
