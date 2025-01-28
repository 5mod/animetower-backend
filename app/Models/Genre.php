<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * @OA\Schema(
 *     schema="Genre",
 *     required={"id", "name", "slug"},
 *     title="Genre Model",
 *     description="Genre model representing anime genres",
 *     @OA\Property(property="id", type="integer", format="int64", example=1),
 *     @OA\Property(property="name", type="string", example="Action"),
 *     @OA\Property(property="slug", type="string", example="action"),
 *     @OA\Property(property="description", type="string", nullable=true, example="Action-packed anime series and movies"),
 *     @OA\Property(property="created_at", type="string", format="date-time"),
 *     @OA\Property(property="updated_at", type="string", format="date-time"),
 *     @OA\Property(property="deleted_at", type="string", format="date-time", nullable=true),
 *     @OA\Property(
 *         property="anime",
 *         type="array",
 *         description="Associated anime",
 *         @OA\Items(ref="#/components/schemas/Anime")
 *     )
 * )
 */

class Genre extends Model
{
    use SoftDeletes;

    protected $fillable = [
        'name',
        'slug',
        'description'
    ];

    protected $dates = ['deleted_at'];

    public function anime()
    {
        return $this->belongsToMany(Anime::class);
    }
} 