<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;


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