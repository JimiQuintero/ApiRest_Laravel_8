<?php

use App\Http\Controllers\API\PacienteController;
use App\Http\Controllers\API\AutenticarController;
use Illuminate\Http\Request;
use Illuminate\Routing\RouteGroup;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

// Route::get('/pacientes', [PacienteController::class, 'index']);
// Route::post('/pacientes', [PacienteController::class, 'store']);
// Route::get('/pacientes/{paciente}', [PacienteController::class, 'show']);
// Route::put('/pacientes/{paciente}', [PacienteController::class, 'update']);
// Route::delete('/pacientes/{paciente}', [PacienteController::class, 'destroy']);

// Utilizando API RESOURCE
//Route::apiResource('pacientes', PacienteController::class);

//Ruta para el registro
Route::post('registro', [AutenticarController::class, 'registro']);

//Ruta para el login (acceso) con token
Route::post('acceso', [AutenticarController::class, 'acceso']);

//Ruta para eliminar token
Route::group(['middleware' => ['auth:sanctum']], function(){
    Route::post('cerrarsesion', [AutenticarController::class, 'cerrarSesion']);
    Route::apiResource('pacientes', PacienteController::class);
});