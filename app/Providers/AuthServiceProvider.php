use Laravel\Passport\Passport;

class AuthServiceProvider extends ServiceProvider
{
    protected $policies = [
        // ...
    ];

    public function boot()
    {
        $this->registerPolicies();
        Passport::routes();
    }
} 