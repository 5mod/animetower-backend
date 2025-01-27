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
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="List of genres retrieved successfully"
     *     )
     * )
     */
    public function index()
    {
        $genres = Genre::withCount('anime')->get();
        return response()->json([
            'status' => 'success',
            'data' => $genres
        ]);
    }

    /**
     * @OA\Post(
     *     path="/v1/genres",
     *     tags={"Genres"},
     *     summary="Create a new genre",
     *     security={{"bearerAuth":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"name"},
     *             @OA\Property(property="name", type="string", example="Action"),
     *             @OA\Property(property="description", type="string", example="Action anime with intense fight scenes")
     *         )
     *     ),
     *     @OA\Response(response=201, description="Genre created successfully"),
     *     @OA\Response(response=422, description="Validation error")
     * )
     */
    public function store(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255|unique:genres',
            'description' => 'nullable|string'
        ]);

        $genre = Genre::create([
            'name' => $request->name,
            'slug' => Str::slug($request->name),
            'description' => $request->description
        ]);

        return response()->json([
            'status' => 'success',
            'message' => 'Genre created successfully',
            'data' => $genre
        ], 201);
    }

    /**
     * @OA\Get(
     *     path="/v1/genres/{id}",
     *     tags={"Genres"},
     *     summary="Get genre details",
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(response=200, description="Genre details retrieved successfully"),
     *     @OA\Response(response=404, description="Genre not found")
     * )
     */
    public function show(Genre $genre)
    {
        $genre->load('anime');
        return response()->json([
            'status' => 'success',
            'data' => $genre
        ]);
    }

    /**
     * @OA\Put(
     *     path="/v1/genres/{id}",
     *     tags={"Genres"},
     *     summary="Update genre details",
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(property="name", type="string"),
     *             @OA\Property(property="description", type="string")
     *         )
     *     ),
     *     @OA\Response(response=200, description="Genre updated successfully"),
     *     @OA\Response(response=404, description="Genre not found"),
     *     @OA\Response(response=422, description="Validation error")
     * )
     */
    public function update(Request $request, Genre $genre)
    {
        $request->validate([
            'name' => 'required|string|max:255|unique:genres,name,' . $genre->id,
            'description' => 'nullable|string'
        ]);

        $genre->update([
            'name' => $request->name,
            'slug' => Str::slug($request->name),
            'description' => $request->description
        ]);

        return response()->json([
            'status' => 'success',
            'message' => 'Genre updated successfully',
            'data' => $genre
        ]);
    }

    /**
     * @OA\Delete(
     *     path="/v1/genres/{id}",
     *     tags={"Genres"},
     *     summary="Delete a genre",
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(response=200, description="Genre deleted successfully"),
     *     @OA\Response(response=404, description="Genre not found")
     * )
     */
    public function destroy(Genre $genre)
    {
        $genre->delete();
        return response()->json([
            'status' => 'success',
            'message' => 'Genre deleted successfully'
        ]);
    }
}
