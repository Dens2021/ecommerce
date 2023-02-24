<?php

namespace App\Http\Controllers;

use App\Models\Entities\UserEntity;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;


class GuestController extends Controller
{
    private const LOGIN_ERROR = 'Email or password is invalid';
    private User $user;

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email:rfc,dns|exists:users',
            'password' => function ($attribute, $value, $fail) use ($request) {

                $this->user = User::where('email', $request->get('email'))->first();

                $isValidPassword = Hash::check($request->get('password'), $this->user->password);
                if (!$isValidPassword) {
                    $fail(self::LOGIN_ERROR);
                }
            },
        ]);

        Auth::login($this->user);
        return redirect('/');

    }

    public function register(Request $request)
    {
        $validated = $request->validate([
            'name' => 'required|min:5|max:255',
            'email' => 'required|email:rfc,dns',
            'password' => 'min:3|required_with:repeatPassword|same:repeatPassword',
            'repeatPassword' => 'min:3',
        ]);

        $user = new UserEntity($validated);
        $user->name = $validated['name'];
        $user->email = $validated['email'];
        $user->password = Hash::make($validated['password']);
        Mail::to("admin@admin.com")->send(new \App\Mail\User($user));
        $user->save();

        return redirect('login');
    }
}
