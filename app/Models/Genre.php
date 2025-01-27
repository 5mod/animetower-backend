<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * @OA\Schema(
 *     schema="Genre",
 *     required={"name", "slug"},
 *     @OA\Property(property="id", type="integer", format="int64", example=1),
 *     @OA\Property(property="name", type="string", example="Action"),
 *     @OA\Property(property="slug", type="string", example="action"),
 *     @OA\Property(property="description", type="string", example="Action anime with intense fight scenes"),
 *     @OA\Property(property="created_at", type="string", format="date-time"),
 *     @OA\Property(property="updated_at", type="string", format="date-time"),
 *     @OA\Property(property="deleted_at", type="string", format="date-time", nullable=true)
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