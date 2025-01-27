<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Anime;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class AnimeController extends Controller
{
    /**
     * @OA\Get(
     *     path="/v1/anime",
     *     tags={"Anime"},
     *     summary="List all anime",
     *     @OA\Response(
     *         response=200,
     *         description="List of anime retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(
     *                 property="data",
     *                 type="array",
     *                 @OA\Items(ref="#/components/schemas/Anime")
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
     *     summary="Create a new anime",
     *     security={{"bearerAuth":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"title","synopsis","type","status","genre_ids"},
     *             @OA\Property(property="title", type="string", example="Naruto"),
     *             @OA\Property(property="synopsis", type="string", example="A young ninja seeks to become the leader of his village"),
     *             @OA\Property(property="type", type="string", enum={"TV","Movie","OVA"}, example="TV"),
     *             @OA\Property(property="status", type="string", enum={"ongoing","completed"}, example="ongoing"),
     *             @OA\Property(property="episodes", type="integer", example=220),
     *             @OA\Property(
     *                 property="genre_ids",
     *                 type="array",
     *                 @OA\Items(type="integer"),
     *                 example={1}
     *             ),
     *             @OA\Property(property="cover_image", type="string", example="naruto.jpg"),
     *             @OA\Property(property="trailer_url", type="string", example="@https://example.com")
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
     *         response=422,
     *         description="Validation error"
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthenticated"
     *     )
     * )
     */
    public function store(Request $request)
    {
        try {
            $request->validate([
                'title' => 'required|string|max:255|unique:anime',
                'synopsis' => 'required|string',
                'type' => 'required|string|in:TV,Movie,OVA',
                'status' => 'required|string|in:ongoing,completed',
                'episodes' => 'nullable|integer',
                'genre_ids' => 'required|array',
                'genre_ids.*' => 'exists:genres,id',
                'cover_image' => 'nullable|string',
                'trailer_url' => 'nullable|string|url'
            ]);

            $anime = Anime::create([
                'title' => $request->title,
                'slug' => Str::slug($request->title),
                'synopsis' => $request->synopsis,
                'type' => $request->type,
                'status' => $request->status,
                'episodes' => $request->episodes,
                'cover_image' => $request->cover_image,
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
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Anime details retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(
     *                 property="data",
     *                 ref="#/components/schemas/Anime"
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="Anime not found"
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
     * @OA\Put(
     *     path="/v1/anime/{id}",
     *     tags={"Anime"},
     *     summary="Update anime details",
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
     *             @OA\Property(property="title", type="string"),
     *             @OA\Property(property="synopsis", type="string"),
     *             @OA\Property(property="type", type="string"),
     *             @OA\Property(property="status", type="string"),
     *             @OA\Property(property="episodes", type="integer"),
     *             @OA\Property(property="genre_ids", type="array", @OA\Items(type="integer")),
     *             @OA\Property(property="cover_image", type="string"),
     *             @OA\Property(property="trailer_url", type="string")
     *         )
     *     ),
     *     @OA\Response(response=200, description="Anime updated successfully"),
     *     @OA\Response(response=404, description="Anime not found"),
     *     @OA\Response(response=422, description="Validation error")
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
            'cover_image' => 'nullable|string',
            'trailer_url' => 'nullable|string|url'
        ]);

        $anime->update([
            'title' => $request->title,
            'slug' => Str::slug($request->title),
            'synopsis' => $request->synopsis,
            'type' => $request->type,
            'status' => $request->status,
            'episodes' => $request->episodes,
            'cover_image' => $request->cover_image,
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
     *     summary="Delete an anime",
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(response=200, description="Anime deleted successfully"),
     *     @OA\Response(response=404, description="Anime not found")
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
