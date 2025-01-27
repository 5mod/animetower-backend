<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::dropIfExists('anime_genre');
        
        Schema::create('anime_genre', function (Blueprint $table) {
            // Foreign keys with explicit table names
            $table->unsignedBigInteger('anime_id');
            $table->unsignedBigInteger('genre_id');
            
            // Create the foreign key constraints
            $table->foreign('anime_id')
                  ->references('id')
                  ->on('anime')
                  ->onDelete('cascade');
                  
            $table->foreign('genre_id')
                  ->references('id')
                  ->on('genres')
                  ->onDelete('cascade');

            // Set composite primary key
            $table->primary(['anime_id', 'genre_id']);
            
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('anime_genre');
    }
};
