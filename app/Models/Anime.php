<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * @OA\Schema(
 *     schema="Anime",
 *     required={"id", "title", "synopsis", "type", "status"},
 *     title="Anime Model",
 *     description="Anime model representing anime entries in the system",
 *     @OA\Property(property="id", type="integer", format="int64", example=1),
 *     @OA\Property(property="title", type="string", example="My Hero Academia"),
 *     @OA\Property(property="slug", type="string", example="my-hero-academia"),
 *     @OA\Property(
 *         property="synopsis", 
 *         type="string", 
 *         example="In a world where people with superpowers known as 'Quirks' are the norm..."
 *     ),
 *     @OA\Property(
 *         property="type", 
 *         type="string", 
 *         enum={"TV", "Movie", "OVA"}, 
 *         example="TV",
 *         description="Type of anime content"
 *     ),
 *     @OA\Property(
 *         property="status", 
 *         type="string", 
 *         enum={"ongoing", "completed"}, 
 *         example="ongoing",
 *         description="Current airing status"
 *     ),
 *     @OA\Property(property="episodes", type="integer", nullable=true, example=13),
 *     @OA\Property(property="poster_image", type="string", nullable=true, example="posters/mha.jpg"),
 *     @OA\Property(property="trailer_url", type="string", nullable=true, example="https://youtube.com/watch?v=abc123"),
 *     @OA\Property(property="score", type="number", format="float", example=4.5, nullable=true),
 *     @OA\Property(property="created_at", type="string", format="date-time"),
 *     @OA\Property(property="updated_at", type="string", format="date-time"),
 *     @OA\Property(property="deleted_at", type="string", format="date-time", nullable=true),
 *     @OA\Property(
 *         property="genres",
 *         type="array",
 *         description="Associated genres",
 *         @OA\Items(ref="#/components/schemas/Genre")
 *     )
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