<?php
// Made-up upload controllers. A control counts only in a canonical, fully bound shape in the method's
// own scope; a shape that only resembles one is evidence (type-candidate, size-candidate, auth-unobserved). Laravel
// route middleware and openemr's globals include sit outside the controller, so a missing check is never visible here:
// no-authorization isn't a rule, and a method without a canonical guard is auth-unobserved.

class UploadController
{
    // Bypass: the client's file name is the stored name, no content check, no size limit, no guard.
    // ruleid: upload-validation.php-laravel.handler
    // ruleid: upload-validation.php-laravel.no-content-type-check
    // ruleid: upload-validation.php-laravel.no-size-limit
    // ruleid: upload-validation.php-laravel.auth-unobserved
    // ok: upload-validation.php-laravel.scan-unchecked
    public function legacy()
    {
        // ruleid: upload-validation.php-laravel.original-name-key
        // ok: upload-validation.php-laravel.scan-candidate
        move_uploaded_file($_FILES['doc']['tmp_name'], UPLOAD_DIR . $_FILES['doc']['name']);
    }

    // ok: upload-validation.php-laravel.handler
    // ok: upload-validation.php-laravel.no-content-type-check
    // ok: upload-validation.php-laravel.type-candidate
    // ok: upload-validation.php-laravel.no-size-limit
    // ok: upload-validation.php-laravel.size-candidate
    // ok: upload-validation.php-laravel.auth-unobserved
    public function store($request)
    {
        if (!Auth::check()) {
            abort(401);
        }
        $file = $request->file('doc');
        if ($file->getSize() > self::MAX) {
            abort(413);
        }
        if (!in_array($file->getMimeType(), self::ALLOWED)) {
            abort(415);
        }
        // ruleid: upload-validation.php-laravel.scan-candidate
        $verdict = $this->clamav->scanFile($file->path());
        if ($verdict['status'] !== 'OK') {
            abort(422);
        }
        // ok: upload-validation.php-laravel.original-name-key
        return $file->storeAs('docs', Str::uuid());
    }

    // The user read only for an audit actor, never checked: auth-unobserved.
    // ruleid: upload-validation.php-laravel.handler
    // ruleid: upload-validation.php-laravel.auth-unobserved
    // ok: upload-validation.php-laravel.no-size-limit
    // ok: upload-validation.php-laravel.no-content-type-check
    public function auditOnly($request)
    {
        $actor = Auth::id() ?? 'anonymous';
        $file = $request->file('doc');
        if ($file->getSize() > self::MAX) {
            abort(413);
        }
        if (!in_array($file->getMimeType(), self::ALLOWED)) {
            abort(415);
        }
        AuditLog::record($actor);
        return $file->storeAs('docs', Str::uuid());
    }

    // An if that only reads the user id isn't the guard (it doesn't reject a missing user): auth-unobserved.
    // ruleid: upload-validation.php-laravel.handler
    // ruleid: upload-validation.php-laravel.auth-unobserved
    public function userRead($request)
    {
        if (Auth::id() === self::BANNED) {
            abort(403);
        }
        $file = $request->file('doc');
        if ($file->getSize() > self::MAX) {
            abort(413);
        }
        if (!in_array($file->getMimeType(), self::ALLOWED)) {
            abort(415);
        }
        return $file->storeAs('docs', Str::uuid());
    }
}

// Controller-level auth middleware guards every action.
class GuardedUploadController
{
    public function __construct()
    {
        $this->middleware('auth');
    }

    // ruleid: upload-validation.php-laravel.handler
    // ok: upload-validation.php-laravel.auth-unobserved
    public function store($request)
    {
        $file = $request->file('doc');
        if ($file->getSize() > self::MAX) {
            abort(413);
        }
        if (!in_array($file->getMimeType(), self::ALLOWED)) {
            abort(415);
        }
        return $file->storeAs('docs', Str::uuid());
    }
}

// a Laravel 11 controller whose auth middleware lives in routes/web.php: auth-unobserved, never a fail.
// a bound detector result in in_array is a real type check in a non-canonical shape: a candidate.
class P3Controller extends Controller
{
    // ruleid: upload-validation.php-laravel.handler
    // ruleid: upload-validation.php-laravel.auth-unobserved
    // ok: upload-validation.php-laravel.no-size-limit
    // ruleid: upload-validation.php-laravel.type-candidate
    // ok: upload-validation.php-laravel.no-content-type-check
    public function store(Request $request)
    {
        $file = $request->file('doc');
        if ($file->getSize() > self::MAX) {
            abort(413);
        }
        $mime = $file->getMimeType();
        if (!in_array($mime, self::ALLOWED)) {
            abort(415);
        }
        return $file->storeAs('docs/' . $request->user()->id, Str::uuid());
    }

    // Laravel validation rules with max: and mimetypes: are the canonical size and type checks; a reversed
    // size comparison elsewhere would only be a candidate.
    // ruleid: upload-validation.php-laravel.handler
    // ok: upload-validation.php-laravel.no-size-limit
    // ok: upload-validation.php-laravel.size-candidate
    // ok: upload-validation.php-laravel.no-content-type-check
    // ok: upload-validation.php-laravel.type-candidate
    public function validated(Request $request)
    {
        $this->authorize('upload', Document::class);
        $request->validate(['doc' => 'required|file|max:10240|mimetypes:application/pdf']);
        return $request->file('doc')->store('docs');
    }

    // ruleid: upload-validation.php-laravel.handler
    // ruleid: upload-validation.php-laravel.size-candidate
    // ok: upload-validation.php-laravel.no-size-limit
    public function reversed(Request $request)
    {
        $this->authorize('upload', Document::class);
        $file = $request->file('doc');
        if (self::MAX < $file->getSize()) {
            abort(413);
        }
        if (!in_array($file->getMimeType(), self::ALLOWED)) {
            abort(415);
        }
        return $file->storeAs('docs', Str::uuid());
    }
}

// ---- More cases.
class Round5UploadController extends Controller
{
    public function __construct() { $this->middleware('auth'); }

    // max:255 on the title's rule string isn't the file's size rule; a max: on a rule string that doesn't name
    // the file is a size-candidate (Laravel's max applies to a file whatever the string says).
    // ok: upload-validation.php-laravel.no-size-limit
    // ruleid: upload-validation.php-laravel.size-candidate
    public function store(Request $request)
    {
        $request->validate(['title' => 'required|max:255', 'doc' => 'required|file|mimes:pdf']);
        $file = $request->file('doc');
        // ruleid: upload-validation.php-laravel.scan-candidate
        $v = $this->clamav->scanFile($file->getRealPath());
        if ($v['status'] !== 'OK') { abort(422); }
        Storage::put(Str::uuid(), $file->get());
    }

    // the size rule only in a comment inside the validate array: no-size-limit.
    // ok: upload-validation.php-laravel.size-candidate
    // ruleid: upload-validation.php-laravel.no-size-limit
    public function store2(Request $request)
    {
        $request->validate([
            'doc' => 'required|file|mimes:pdf', // TODO 'max:10240'
        ]);
        $file = $request->file('doc');
        // ruleid: upload-validation.php-laravel.scan-candidate
        $v = $this->clamav->scanFile($file->getRealPath());
        if ($v['status'] !== 'OK') { abort(422); }
        Storage::put(Str::uuid(), $file->get());
    }

    // A max: and mimes: on the file's own rule string are the size and type checks; a scan verdict read in a
    // non-canonical way is scan-unchecked.
    // ok: upload-validation.php-laravel.no-size-limit
    // ok: upload-validation.php-laravel.size-candidate
    // ok: upload-validation.php-laravel.no-content-type-check
    // ruleid: upload-validation.php-laravel.scan-unchecked
    // ruleid: upload-validation.php-laravel.handler
    public function store3(Request $request)
    {
        $request->validate(['doc' => 'required|file|max:10240|mimes:pdf']);
        $file = $request->file('doc');
        // ruleid: upload-validation.php-laravel.scan-candidate
        $v = $this->clamav->scanFile($file->getRealPath());
        if (!$v) { abort(422); }
        Storage::put(Str::uuid(), $file->get());
    }

}

class Round5GuardController extends Controller
{
    // A 401 status set without ending the handler isn't the guard: auth unobserved.
    // ruleid: upload-validation.php-laravel.auth-unobserved
    // ruleid: upload-validation.php-laravel.handler
    public function store4(Request $request)
    {
        if (!Auth::check()) { http_response_code(401); }
        $file = $request->file('doc');
        if ($file->getSize() > self::MAX) { abort(413); }
        if (!in_array($file->getMimeType(), self::ALLOWED)) { abort(415); }
        Storage::put(Str::uuid(), $file->get());
    }
}
