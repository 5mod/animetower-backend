<?php

namespace Database\Seeders;

use App\Models\Anime;
use Illuminate\Database\Seeder;
use Illuminate\Support\Str;

class AnimeSeeder extends Seeder
{
    public function run()
    {
        $animes = [
            [
                'title' => 'Naruto',
                'synopsis' => 'A young ninja seeks to become the leader of his village.',
                'type' => 'TV',
                'status' => 'completed',
                'episodes' => 220,
            ],
            [
                'title' => 'One Piece',
                'synopsis' => 'Monkey D. Luffy sets out to become the King of the Pirates.',
                'type' => 'TV',
                'status' => 'ongoing',
                'episodes' => 1000,
            ],
            // Add more anime as needed
        ];

        foreach ($animes as $anime) {
            Anime::create([
                'title' => $anime['title'],
                'slug' => Str::slug($anime['title']),
                'synopsis' => $anime['synopsis'],
                'type' => $anime['type'],
                'status' => $anime['status'],
                'episodes' => $anime['episodes'],
            ]);
        }
    }
} 