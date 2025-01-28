<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * @OA\Schema(
 *     schema="Anime",
 *     required={"title", "slug", "synopsis"},
 *     @OA\Property(property="id", type="integer", format="int64", example=1),
 *     @OA\Property(property="title", type="string", example="Naruto"),
 *     @OA\Property(property="slug", type="string", example="naruto"),
 *     @OA\Property(property="synopsis", type="string", example="A young ninja seeks to become the leader of his village"),
 *     @OA\Property(property="type", type="string", example="TV"),
 *     @OA\Property(property="status", type="string", example="ongoing"),
 *     @OA\Property(property="episodes", type="integer", example=220),
 *     @OA\Property(property="cover_image", type="string", example="naruto.jpg"),
 *     @OA\Property(property="trailer_url", type="string", example="https://youtube.com/watch?v=..."),
 *     @OA\Property(property="score", type="number", format="float", example=4.5),
 *     @OA\Property(property="created_at", type="string", format="date-time"),
 *     @OA\Property(property="updated_at", type="string", format="date-time"),
 *     @OA\Property(property="deleted_at", type="string", format="date-time", nullable=true)
 * )
 */
class Anime extends Model
{
    use SoftDeletes;

    protected $table = 'anime';

    protected $fillable = [
        'title',
        'slug',
        'synopsis',
        'type',
        'status',
        'episodes',
        'poster_image',
        'trailer_url',
        'score'
    ];

    protected $casts = [
        'score' => 'decimal:2'
    ];

    protected $dates = ['deleted_at'];

    public function genres()
    {
        return $this->belongsToMany(Genre::class);
    }
} 