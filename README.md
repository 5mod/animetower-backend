# AnimeTower API

A robust RESTful API for managing anime content, built with Laravel. This API provides comprehensive endpoints for anime management, user authentication, and content organization.

## Features

### Authentication & Authorization
- JWT-based authentication using Laravel Passport
- Two-factor authentication (2FA) with time-based codes
- Role-based access control (Admin/User)
- Email verification system
- Secure password reset functionality

### User Management
- Complete user registration and login system
- Profile management with avatar support
- Admin/User role distinction
- Two-factor authentication toggle
- Account status control
- Profile picture upload and management
- Email verification with expiring codes

### Anime Management
- Complete CRUD operations for anime entries
- Poster image upload and management
- Soft delete and restore functionality
- Advanced filtering and search capabilities
- Pagination support
- Anime categorization with genres
- Trailer URL support
- Episode tracking
- Status tracking (ongoing/completed...etc)
- Type categorization (TV/Movie/OVA...etc)

### Genre System
- Genre categorization and management
- Many-to-many relationships with anime
- Soft delete support for genres
- Genre restoration capability

### Media Management
- Image upload support for:
  - User avatars
  - Anime posters
- Secure file storage
- File validation
- Automatic old file cleanup


## Requirements

- PHP >= 8.2
- Composer
- MySQL >= 8.0
- Laravel 11
  

## Installation

1. Clone the repository:

bash
git clone https://github.com/5mod/animetower-backend.git
cd animetower-backend

2. Install dependencies:

bash
composer install

3. Create and configure environment file:
bash
cp .env.example .env


4. Configure your database and mail settings in `.env`:

env
DB_CONNECTION=DB
DB_HOST=Your DB host
DB_PORT=Your DB port
DB_DATABASE=anime-tower
DB_USERNAME=your_username
DB_PASSWORD=your_password
MAIL_MAILER=smtp
MAIL_HOST=your_mail_host
MAIL_PORT=your_mail_port
MAIL_USERNAME=your_mail_username
MAIL_PASSWORD=your_mail_password
MAIL_ENCRYPTION=your_mail_encryption
MAIL_FROM_ADDRESS=your_email
MAIL_FROM_NAME="${APP_NAME}"
PASSPORT_CLIENT_ID=your_passport_client_id
PASSPORT_CLIENT_SECRET=your_passport_client_secret

5. Run the setup commands:

bash
php artisan storage:link
php artisan key:generate
php artisan migrate:fresh
php artisan passport:install --api
php artisan passport:client --personal

6. Run the development server:

bash
php artisan serve

7. Generate API documentation:

bash
php artisan l5-swagger:generate

## API Documentation

The API documentation is available at:

https://animetower-backend.7modo.com/api/documentation
