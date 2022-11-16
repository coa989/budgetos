<?php

namespace App\Enums;

enum AccountType: string
{
    case BANK = 'bank';
    case CASH = 'cash';
    case SAVINGS = 'savings';
}
