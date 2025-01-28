<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Anime;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Storage;

/**
 * @OA\Tag(
 *     name="Anime",
 *     description="API Endpoints for anime management"
 * )
 */

/**
 * @OA\Schema(
 *     schema="Anime",
 *     required={"id", "title", "synopsis", "type", "status"},
 *     @OA\Property(property="id", type="integer", example=1),
 *     @OA\Property(property="title", type="string", example="My Hero Academia"),
 *     @OA\Property(property="slug", type="string", example="my-hero-academia"),
 *     @OA\Property(property="synopsis", type="string", example="In a world where people with superpowers known as 'Quirks' are the norm..."),
 *     @OA\Property(property="type", type="string", enum={"TV", "Movie", "OVA"}, example="TV"),
 *     @OA\Property(property="status", type="string", enum={"ongoing", "completed"}, example="ongoing"),
 *     @OA\Property(property="episodes", type="integer", nullable=true, example=13),
 *     @OA\Property(property="poster_image", type="string", nullable=true, example="posters/mha.jpg"),
 *     @OA\Property(property="trailer_url", type="string", nullable=true, example="https://youtube.com/watch?v=abc123"),
 *     @OA\Property(property="created_at", type="string", format="date-time"),
 *     @OA\Property(property="updated_at", type="string", format="date-time"),
 *     @OA\Property(
 *         property="genres",
 *         type="array",
 *         @OA\Items(ref="#/components/schemas/Genre")
 *     )
 * )
 */

/**
 * @OA\Schema(
 *     schema="Genre",
 *     required={"id", "name"},
 *     @OA\Property(property="id", type="integer", example=1),
 *     @OA\Property(property="name", type="string", example="Action"),
 *     @OA\Property(property="created_at", type="string", format="date-time"),
 *     @OA\Property(property="updated_at", type="string", format="date-time")
 * )
 */


class AnimeController extends Controller
{
    /**
     * @OA\Get(
     *     path="/v1/anime",
     *     tags={"Anime"},
     *     summary="List all anime",
     *     description="Get a paginated list of anime with optional filters and search. Results are sorted by latest first.",
     *     @OA\Parameter(
     *         name="search",
     *         in="query",
     *         description="Search by title or description",
     *         required=false,
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Parameter(
     *         name="genre",
     *         in="query",
     *         description="Filter by genre ID",
     *         required=false,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Parameter(
     *         name="status",
     *         in="query",
     *         description="Filter by status (ongoing, completed)",
     *         required=false,
     *         @OA\Schema(type="string", enum={"ongoing", "completed"})
     *     ),
     *     @OA\Parameter(
     *         name="page",
     *         in="query",
     *         description="Page number for pagination",
     *         required=false,
     *         @OA\Schema(type="integer", default=1)
     *     ),
     *     @OA\Parameter(
     *         name="per_page",
     *         in="query",
     *         description="Items per page (max: 50)",
     *         required=false,
     *         @OA\Schema(type="integer", default=15)
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="List retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 @OA\Property(property="current_page", type="integer", example=1),
     *                 @OA\Property(property="data", type="array", @OA\Items(ref="#/components/schemas/Anime")),
     *                 @OA\Property(property="first_page_url", type="string"),
     *                 @OA\Property(property="from", type="integer"),
     *                 @OA\Property(property="last_page", type="integer"),
     *                 @OA\Property(property="last_page_url", type="string"),
     *                 @OA\Property(property="next_page_url", type="string", nullable=true),
     *                 @OA\Property(property="path", type="string"),
     *                 @OA\Property(property="per_page", type="integer"),
     *                 @OA\Property(property="prev_page_url", type="string", nullable=true),
     *                 @OA\Property(property="to", type="integer"),
     *                 @OA\Property(property="total", type="integer")
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(
     *                 property="message",
     *                 type="object",
     *                 @OA\Property(
     *                     property="per_page",
     *                     type="array",
     *                     @OA\Items(type="string", example="The per page must not be greater than 50.")
     *                 )
     *             )
     *         )
     *     )
     * )
     */
    public function index()
    {
        $anime = Anime::with('genres')->get();
        return response()->json([
            'status' => 'success',
            'data' => $anime
        ]);
    }

    /**
     * @OA\Post(
     *     path="/v1/anime",
     *     tags={"Anime"},
     *     summary="Create new anime",
     *     description="Create a new anime entry with genres (Admin only)",
     *     security={{"bearerAuth":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"title", "synopsis", "type", "status", "genre_ids"},
     *             @OA\Property(
     *                 property="title",
     *                 type="string",
     *                 example="My Anime Title",
     *                 description="Anime title (must be unique)"
     *             ),
     *             @OA\Property(
     *                 property="synopsis",
     *                 type="string",
     *                 example="Detailed description of the anime",
     *                 description="Anime plot summary"
     *             ),
     *             @OA\Property(
     *                 property="type",
     *                 type="string",
     *                 enum={"TV", "Movie", "OVA"},
     *                 example="TV",
     *                 description="Type of anime"
     *             ),
     *             @OA\Property(
     *                 property="status",
     *                 type="string",
     *                 enum={"ongoing", "completed"},
     *                 example="ongoing",
     *                 description="Current airing status"
     *             ),
     *             @OA\Property(
     *                 property="episodes",
     *                 type="integer",
     *                 example=12,
     *                 description="Number of episodes (optional)",
     *                 nullable=true
     *             ),
     *             @OA\Property(
     *                 property="trailer_url",
     *                 type="string",
     *                 example="https://youtube.com/watch?v=...",
     *                 description="URL to trailer video (optional)",
     *                 nullable=true
     *             ),
     *             @OA\Property(
     *                 property="genre_ids",
     *                 type="array",
     *                 @OA\Items(type="integer"),
     *                 example={1, 3},
     *                 description="Array of genre IDs"
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Anime created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Anime created successfully"),
     *             @OA\Property(
     *                 property="data",
     *                 ref="#/components/schemas/Anime"
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Unauthenticated")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Admin access required")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(
     *                 property="message",
     *                 type="object",
     *                 @OA\Property(
     *                     property="title",
     *                     type="array",
     *                     @OA\Items(type="string", example="The title field is required.")
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Failed to create anime"),
     *             @OA\Property(property="error", type="string", example="Error message details")
     *         )
     *     )
     * )
     */
    public function store(Request $request)
    {
        $request->validate([
            'title' => 'required|string|max:255|unique:anime',
            'synopsis' => 'required|string',
            'type' => 'required|string|in:TV,Movie,OVA',
            'status' => 'required|string|in:ongoing,completed',
            'episodes' => 'nullable|integer',
            'trailer_url' => 'nullable|string|url',
            'genre_ids' => 'required|array',
            'genre_ids.*' => 'exists:genres,id'
        ]);

        try {
            $anime = Anime::create([
                'title' => $request->title,
                'slug' => Str::slug($request->title),
                'synopsis' => $request->synopsis,
                'type' => $request->type,
                'status' => $request->status,
                'episodes' => $request->episodes,
                'trailer_url' => $request->trailer_url
            ]);

            $anime->genres()->attach($request->genre_ids);

            return response()->json([
                'status' => 'success',
                'message' => 'Anime created successfully',
                'data' => $anime->load('genres')
            ], 201);

        } catch (\Exception $e) {
            \Log::error('Anime creation error: ' . $e->getMessage());
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to create anime',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * @OA\Get(
     *     path="/v1/anime/{id}",
     *     tags={"Anime"},
     *     summary="Get anime details",
     *     description="Get detailed information about a specific anime including its genres and episodes",
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         description="ID of anime to retrieve",
     *         required=true,
     *         @OA\Schema(type="integer", format="int64")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Anime details retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 allOf={
     *                     @OA\Schema(ref="#/components/schemas/Anime"),
     *                     @OA\Schema(
     *                         @OA\Property(
     *                             property="genres",
     *                             type="array",
     *                             @OA\Items(ref="#/components/schemas/Genre")
     *                         ),
     *                         
     *                     )
     *                 }
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="Anime not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Anime not found")
     *         )
     *     )
     * )
     */
    public function show(Anime $anime)
    {
        return response()->json([
            'status' => 'success',
            'data' => $anime->load('genres')
        ]);
    }

    /**
     * @OA\Post(
     *     path="/v1/anime/{id}/poster",
     *     tags={"Anime"},
     *     summary="Upload anime poster image",
     *     description="Upload a new poster image for an anime (Admin only)",
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         description="ID of anime",
     *         required=true,
     *         @OA\Schema(type="integer", format="int64")
     *     ),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\MediaType(
     *             mediaType="multipart/form-data",
     *             @OA\Schema(
     *                 required={"poster_image"},
     *                 @OA\Property(
     *                     property="poster_image",
     *                     type="string",
     *                     format="binary",
     *                     description="Image file (max 5MB). Allowed types: jpg, jpeg, png, gif, bmp, svg, webp"
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Poster image updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Poster image updated successfully"),
     *             @OA\Property(property="data", ref="#/components/schemas/Anime")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Unauthenticated")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Admin access required")
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="Anime not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Anime not found")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(
     *                 property="message",
     *                 type="object",
     *                 @OA\Property(
     *                     property="poster_image",
     *                     type="array",
     *                     @OA\Items(type="string", example="The poster image is required.")
     *                 )
     *             )
     *         )
     *     )
     * )
     */
    public function updatePoster(Request $request, Anime $anime)
    {
        $request->validate([
            'poster_image' => 'required|image|mimes:jpg,jpeg,png,gif,bmp,svg,webp|max:5120'
        ]);

        try {
            // Delete old poster image if exists
            if ($anime->poster_image) {
                Storage::disk('public')->delete($anime->poster_image);
            }

            // Store new poster image
            $path = $request->file('poster_image')->store('posters', 'public');

            $anime->update([
                'poster_image' => $path
            ]);

            return response()->json([
                'status' => 'success',
                'message' => 'Poster image updated successfully',
                'data' => $anime->load('genres')
            ]);

        } catch (\Exception $e) {
            \Log::error('Poster image upload error: ' . $e->getMessage());
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to upload poster image',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * @OA\Put(
     *     path="/v1/anime/{id}",
     *     tags={"Anime"},
     *     summary="Update anime",
     *     description="Update an existing anime entry (Admin only)",
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         description="ID of anime to update",
     *         required=true,
     *         @OA\Schema(type="integer", format="int64")
     *     ),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(
     *                 property="title",
     *                 type="string",
     *                 example="Updated Anime Title"
     *             ),
     *             @OA\Property(
     *                 property="description",
     *                 type="string",
     *                 example="Updated description"
     *             ),
     *             @OA\Property(
     *                 property="status",
     *                 type="string",
     *                 enum={"ongoing", "completed"},
     *                 example="completed"
     *             ),
     *             @OA\Property(
     *                 property="release_date",
     *                 type="string",
     *                 format="date",
     *                 example="2024-01-15"
     *             ),
     *             @OA\Property(
     *                 property="poster_image",
     *                 type="string",
     *                 format="binary",
     *                 description="New poster image (optional)"
     *             ),
     *             @OA\Property(
     *                 property="genres",
     *                 type="array",
     *                 @OA\Items(type="integer"),
     *                 example={1, 3}
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Anime updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Anime updated successfully"),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 allOf={
     *                     @OA\Schema(ref="#/components/schemas/Anime"),
     *                     @OA\Schema(
     *                         @OA\Property(
     *                             property="genres",
     *                             type="array",
     *                             @OA\Items(ref="#/components/schemas/Genre")
     *                         )
     *                     )
     *                 }
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Unauthenticated")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Admin access required")
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="Anime not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Anime not found")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(
     *                 property="message",
     *                 type="object",
     *                 @OA\Property(
     *                     property="status",
     *                     type="array",
     *                     @OA\Items(type="string", example="The selected status is invalid.")
     *                 )
     *             )
     *         )
     *     )
     * )
     */
    public function update(Request $request, Anime $anime)
    {
        $request->validate([
            'title' => 'required|string|max:255|unique:anime,title,' . $anime->id,
            'synopsis' => 'required|string',
            'type' => 'required|string|in:TV,Movie,OVA',
            'status' => 'required|string|in:ongoing,completed',
            'episodes' => 'nullable|integer',
            'genre_ids' => 'required|array',
            'genre_ids.*' => 'exists:genres,id',
            'trailer_url' => 'nullable|string|url'
        ]);

        $anime->update([
            'title' => $request->title,
            'slug' => Str::slug($request->title),
            'synopsis' => $request->synopsis,
            'type' => $request->type,
            'status' => $request->status,
            'episodes' => $request->episodes,
            'trailer_url' => $request->trailer_url
        ]);

        $anime->genres()->sync($request->genre_ids);

        return response()->json([
            'status' => 'success',
            'message' => 'Anime updated successfully',
            'data' => $anime->load('genres')
        ]);
    }

    /**
     * @OA\Delete(
     *     path="/v1/anime/{id}",
     *     tags={"Anime"},
     *     summary="Delete anime",
     *     description="Delete an anime and its associated data (Admin only)",
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         description="ID of anime to delete",
     *         required=true,
     *         @OA\Schema(type="integer", format="int64")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Anime deleted successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Anime deleted successfully")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Unauthenticated")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Admin access required")
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="Anime not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Anime not found")
     *         )
     *     )
     * )
     */
    public function destroy(Anime $anime)
    {
        $anime->delete();
        return response()->json([
            'status' => 'success',
            'message' => 'Anime deleted successfully'
        ]);
    }
}
