<?php

namespace App\Http\Resources;

use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Support\Str;

class PacienteResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array|\Illuminate\Contracts\Support\Arrayable|\JsonSerializable
     */
    public function toArray($request)
    {
        // return parent::toArray($request);
        return [
            // 'identificador' => $this->id,
            // 'id' => $this->id
            'id' => $this->id,
            'nombres' => Str::of($this->nombres)->upper(),
            'apellidos' => Str::of($this->apellidos)->upper(),
            'edad' => $this->edad,
            'sexo' => $this->sexo,
            'dni' => $this->dni,
            'tipo_sangre' => $this->tipo_sangre,
            'telefono' => $this->telefono,
            'correo' => $this->correo,
            'direccion' => $this->direccion,
            'fecha_creado' => $this->created_at->format('d-m-Y'),
            'fecha_modificado' => $this->updated_at->format('d-m-Y')
            // 'created_at' => $this->created_at->format('d-m-Y'),
            // 'updated_at' => $this->updated_at->format('d-m-Y')
        ];
    }

    public function with($request)
    {
        return [
            'res' => true
        ];
    }
}