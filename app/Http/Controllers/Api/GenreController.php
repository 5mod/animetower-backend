<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Genre;
use Illuminate\Http\Request;
use Illuminate\Support\Str;


class GenreController extends Controller
{
    /**
     * @OA\Get(
     *     path="/v1/genres",
     *     tags={"Genres"},
     *     summary="List all genres",
     *     description="Get a list of all genres with their anime count",
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="List of genres retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(
     *                 property="data",
     *                 type="array",
     *                 @OA\Items(
     *                     allOf={
     *                         @OA\Schema(ref="#/components/schemas/Genre"),
     *                         @OA\Schema(
     *                             @OA\Property(
     *                                 property="anime_count",
     *                                 type="integer",
     *                                 example=5,
     *                                 description="Number of anime in this genre"
     *                             )
     *                         )
     *                     }
     *                 )
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
     *     )
     * )
     */
    public function index()
    {
        try {
            $genres = Genre::withCount('anime')->get();
            return response()->json([
                'status' => 'success',
                'data' => $genres
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to retrieve genres'
            ], 500);
        }
    }

    /**
     * @OA\Post(
     *     path="/v1/genres",
     *     tags={"Genres"},
     *     summary="Create a new genre",
     *     description="Create a new genre (Admin only)",
     *     security={{"bearerAuth":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"name"},
     *             @OA\Property(
     *                 property="name",
     *                 type="string",
     *                 example="Action",
     *                 description="Genre name (must be unique)"
     *             ),
     *             @OA\Property(
     *                 property="description",
     *                 type="string",
     *                 example="Action anime with intense fight scenes",
     *                 description="Optional genre description"
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Genre created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Genre created successfully"),
     *             @OA\Property(property="data", ref="#/components/schemas/Genre")
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
     *                     property="name",
     *                     type="array",
     *                     @OA\Items(type="string", example="The name field is required.")
     *                 )
     *             )
     *         )
     *     )
     * )
     */
    public function store(Request $request)
    {
        try {
            $validated = $request->validate([
                'name' => 'required|string|max:255|unique:genres',
                'description' => 'nullable|string'
            ]);

            $genre = Genre::create([
                'name' => $validated['name'],
                'slug' => Str::slug($validated['name']),
                'description' => $validated['description'] ?? null
            ]);

            return response()->json([
                'status' => 'success',
                'message' => 'Genre created successfully',
                'data' => $genre
            ], 201);
        } catch (\Illuminate\Validation\ValidationException $e) {
            return response()->json([
                'status' => 'error',
                'message' => $e->errors()
            ], 422);
        } catch (\Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to create genre'
            ], 500);
        }
    }

    /**
     * @OA\Get(
     *     path="/v1/genres/{id}",
     *     tags={"Genres"},
     *     summary="Get genre details",
     *     description="Get detailed information about a specific genre including its anime",
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         description="ID of genre to retrieve",
     *         required=true,
     *         @OA\Schema(type="integer", format="int64")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Genre details retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 allOf={
     *                     @OA\Schema(ref="#/components/schemas/Genre"),
     *                     @OA\Schema(
     *                         @OA\Property(
     *                             property="anime",
     *                             type="array",
     *                             @OA\Items(ref="#/components/schemas/Anime")
     *                         )
     *                     )
     *                 }
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="Genre not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Genre not found")
     *         )
     *     )
     * )
     */
    public function show(Genre $genre)
    {
        try {
            $genre->load('anime');
            return response()->json([
                'status' => 'success',
                'data' => $genre
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to retrieve genre details'
            ], 500);
        }
    }

    /**
     * @OA\Put(
     *     path="/v1/genres/{id}",
     *     tags={"Genres"},
     *     summary="Update genre details",
     *     description="Update an existing genre (Admin only)",
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         description="ID of genre to update",
     *         required=true,
     *         @OA\Schema(type="integer", format="int64")
     *     ),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"name"},
     *             @OA\Property(
     *                 property="name",
     *                 type="string",
     *                 example="Updated Genre Name",
     *                 description="New genre name (must be unique)"
     *             ),
     *             @OA\Property(
     *                 property="description",
     *                 type="string",
     *                 example="Updated genre description",
     *                 description="Optional genre description"
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Genre updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Genre updated successfully"),
     *             @OA\Property(property="data", ref="#/components/schemas/Genre")
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
     *         description="Genre not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Genre not found")
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
     *                     property="name",
     *                     type="array",
     *                     @OA\Items(type="string", example="The name has already been taken.")
     *                 )
     *             )
     *         )
     *     )
     * )
     */
    public function update(Request $request, Genre $genre)
    {
        try {
            $validated = $request->validate([
                'name' => 'required|string|max:255|unique:genres,name,' . $genre->id,
                'description' => 'nullable|string'
            ]);

            $genre->update([
                'name' => $validated['name'],
                'slug' => Str::slug($validated['name']),
                'description' => $validated['description'] ?? null
            ]);

            return response()->json([
                'status' => 'success',
                'message' => 'Genre updated successfully',
                'data' => $genre
            ]);
        } catch (\Illuminate\Validation\ValidationException $e) {
            return response()->json([
                'status' => 'error',
                'message' => $e->errors()
            ], 422);
        } catch (\Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to update genre'
            ], 500);
        }
    }

    /**
     * @OA\Delete(
     *     path="/v1/genres/{id}",
     *     tags={"Genres"},
     *     summary="Delete a genre",
     *     description="Delete an existing genre (Admin only)",
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         description="ID of genre to delete",
     *         required=true,
     *         @OA\Schema(type="integer", format="int64")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Genre deleted successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Genre deleted successfully")
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
     *         description="Genre not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Genre not found")
     *         )
     *     )
     * )
     */
    public function destroy(Genre $genre)
    {
        try {
            $genre->delete();
            return response()->json([
                'status' => 'success',
                'message' => 'Genre deleted successfully'
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to delete genre'
            ], 500);
        }
    }
}
