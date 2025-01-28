<?php

namespace App\Http\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Routing\Controller as BaseController;

/**
 * @OA\Info(
 *     version="1.0.0",
 *     title="AnimeTower API Documentation",
 *     description="API documentation for AnimeTower application",
 *     @OA\Contact(
 *         email="mahmoud@7modo.com",
 *         name="AnimeTower Support"
 *     ),
 *     @OA\License(
 *         name="MIT",
 *         url="https://opensource.org/licenses/MIT"
 *     )
 * )
 *
 * @OA\Server(
 *     url=L5_SWAGGER_CONST_HOST,
 *     description="AnimeTower API Server"
 * )
 * 
 * @OA\SecurityScheme(
 *     securityScheme="bearerAuth",
 *     type="http",
 *     scheme="bearer",
 *     bearerFormat="JWT"
 * )
 * 
 * @OA\Tag(
 *     name="Authentication",
 *     description="API Endpoints for user authentication",
 *     @OA\ExternalDocumentation(
 *         url="https://example.com/docs/authentication",
 *         description="Learn more about authentication"
 *     )
 * )
 * 
 * @OA\Tag(
 *     name="Two-Factor Authentication",
 *     description="API Endpoints for 2FA management"
 * )
 * 
 * @OA\Tag(
 *     name="Email Verification",
 *     description="API Endpoints for email verification"
 * )
 * 
 * @OA\Tag(
 *     name="Password Management",
 *     description="API Endpoints for password management"
 * )
 * 
 * @OA\Tag(
 *     name="User Management",
 *     description="API Endpoints for user management"
 * )
 * 
 * @OA\Tag(
 *     name="Account Management",
 *     description="API Endpoints for account settings and profile"
 * )
 * 
 * @OA\Tag(
 *     name="Genres",
 *     description="API Endpoints for genre management"
 * )
 * 
 * @OA\Tag(
 *     name="Anime",
 *     description="API Endpoints for anime management"
 * )
 */
class Controller extends BaseController
{
    use AuthorizesRequests, ValidatesRequests;
}
