<?php

namespace App\Http\Controllers;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    
    protected $model;

    public function __construct(){
        $this->model = new User();
    }
  
    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email' => 'required|email',
            'password' => 'required|string'
        ]);

        try{
            
            if(!Auth::attempt($credentials)){
                return response(['message' => "Account is not registered"], 200);
            } 

            $user = $this->model->where('email', $request->email)->first();            
            $token = $user->createToken($request->email . Str::random(8))->plainTextToken;

            return response(['token' => $token], 200);

        }catch(\Exception $e){
            return response(['message' => $e->getMessage()], 400);
        }
    }

    public function register(Request $request)
    { // Validation
        try {
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password), // Hash the password
            ]);

            return response()->json($user, 201);
            return response(['message' => 'User registered successfully', 'user' => $user], 201);
        } catch (\Throwable $e) {
            //throw $th;
           
            return response()->json([
                'status' => false,
                'message' => $e->getMessage()
            ], 500); 
            return response("Errors");
        }
    }
  
}