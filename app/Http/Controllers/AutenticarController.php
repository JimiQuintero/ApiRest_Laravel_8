<?php

namespace App\Http\Controllers;

use App\Http\Requests\AccesoRequest;
use App\Http\Requests\RegistroRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AutenticarController extends Controller
{
    //Metodo register
    public function registro(RegistroRequest $request) {
        $user = new User();
        $user->name = $request->name; 
        $user->email = $request->email; 
        $user->password = bcrypt($request->password);
        $user->save();
        
        return response()-> json([
            'res' => true,
            'msg' => 'Usuario registrado correctamente'
        ],200);
    }


    //Metodo login
    public function acceso(AccesoRequest $request) {
        $user = User::where('email', $request->email)->first();
 
        if (! $user || ! Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                'message' => ['Las credenciales son incorrectas!!!'],
            ]);
        }
     
        $token = $user->createToken($request->email)->plainTextToken;

        return response() -> json([
            'res' => true,
            'token' => $token
        ],200);
    }

    //Metodo logout
    public function cerrarSesion(Request $request) {
        // Revoke the token that was used to authenticate the current request...
        $request->user()->currentAccessToken()->delete();

        return response() -> json([
            'res' => true,
            'message' => "Token eliminado corrrectamente"
        ],200);
    }
}