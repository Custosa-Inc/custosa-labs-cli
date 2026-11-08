<?php

class Patient extends Model
{
    // ruleid: write-fields-allowlisted.php-laravel.guarded-empty
    // ok: write-fields-allowlisted.php-laravel.fillable
    protected $guarded = [];
    // ruleid: write-fields-allowlisted.php-laravel.fillable
    // ok: write-fields-allowlisted.php-laravel.guarded-empty
    protected $fillable = ['name', 'dob'];
}

class PatientController extends Controller
{
    public function store(StorePatientRequest $request)
    {
        // ruleid: write-fields-allowlisted.php-laravel.write
        // ruleid: write-fields-allowlisted.php-laravel.body-into-write
        $a = Patient::create($request->all());
        // ok: write-fields-allowlisted.php-laravel.write
        // ok: write-fields-allowlisted.php-laravel.body-into-write
        $b = Patient::create($request->validated());
        // ok: write-fields-allowlisted.php-laravel.write
        $c = Patient::create([
            'name' => $request->input('name'),
            // ok: write-fields-allowlisted.php-laravel.identity-field
            'owner_id' => Auth::id(),
            // ruleid: write-fields-allowlisted.php-laravel.identity-from-request
            // ruleid: write-fields-allowlisted.php-laravel.identity-field
            'role' => $request->input('role'),
        ]);
        // Bypass (sprint): except() is a denylist, not an allowlist.
        // ruleid: write-fields-allowlisted.php-laravel.write
        // ruleid: write-fields-allowlisted.php-laravel.denylist
        $a->fill($request->except(['role', 'owner_id']));
        $input = $request->all();
        // ruleid: write-fields-allowlisted.php-laravel.write
        // ruleid: write-fields-allowlisted.php-laravel.body-into-write
        $a->update($input);
        // ok: write-fields-allowlisted.php-laravel.denylist
        // ok: write-fields-allowlisted.php-laravel.identity-from-request
        return response()->json($request->only(['name']));
    }
}
