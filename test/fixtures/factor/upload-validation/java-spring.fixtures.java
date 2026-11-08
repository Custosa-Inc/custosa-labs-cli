// Made-up Spring controllers. A control counts only in a canonical, fully bound shape in the method's
// own scope; a shape that only resembles one is evidence (type-candidate, size-candidate, auth-unobserved). Spring
// security is usually configured centrally (a SecurityFilterChain), so a missing check in a controller is never
// visible: no-authorization isn't a rule here, and a method without a canonical guard is auth-unobserved.
@RestController
class UploadController {
    // ruleid: upload-validation.java-spring.handler
    // ruleid: upload-validation.java-spring.no-content-type-check
    // ruleid: upload-validation.java-spring.no-size-limit
    // ruleid: upload-validation.java-spring.auth-unobserved
    // ok: upload-validation.java-spring.scan-unchecked
    String upload(@RequestPart("file") MultipartFile file) throws Exception {
        // ruleid: upload-validation.java-spring.original-name-key
        // ok: upload-validation.java-spring.scan-candidate
        file.transferTo(Paths.get("/data", file.getOriginalFilename()));
        return "ok";
    }

    // ok: upload-validation.java-spring.handler
    // ok: upload-validation.java-spring.no-content-type-check
    // ok: upload-validation.java-spring.type-candidate
    // ok: upload-validation.java-spring.no-size-limit
    // ok: upload-validation.java-spring.size-candidate
    // ok: upload-validation.java-spring.auth-unobserved
    @PreAuthorize("hasRole('CLINICIAN')")
    String safe(@RequestPart("file") MultipartFile file) throws Exception {
        if (file.getSize() > MAX_SIZE) throw new IllegalArgumentException();
        String type = tika.detect(file.getInputStream());
        if (!ALLOWED.contains(type)) throw new IllegalArgumentException();
        // ruleid: upload-validation.java-spring.scan-candidate
        if (!clamavClient.scan(file.getInputStream()).isClean()) throw new IllegalStateException();
        // ok: upload-validation.java-spring.original-name-key
        file.transferTo(Paths.get("/data", UUID.randomUUID().toString()));
        return type;
    }

    // A Principal read only for an audit actor, never checked: auth-unobserved.
    // ruleid: upload-validation.java-spring.handler
    // ruleid: upload-validation.java-spring.auth-unobserved
    // ok: upload-validation.java-spring.no-size-limit
    // ok: upload-validation.java-spring.no-content-type-check
    String auditOnly(@RequestPart("file") MultipartFile file, Principal principal) throws Exception {
        String actor = principal != null ? principal.getName() : "anonymous";
        if (file.getSize() > MAX_SIZE) throw new IllegalArgumentException();
        String type = tika.detect(file.getInputStream());
        if (!ALLOWED.contains(type)) throw new IllegalArgumentException();
        audit.record(actor);
        file.transferTo(Paths.get("/data", UUID.randomUUID().toString()));
        return type;
    }

    // A missing principal rejected before the upload is read: authorization.
    // ruleid: upload-validation.java-spring.handler
    // ok: upload-validation.java-spring.auth-unobserved
    String guarded(@RequestPart("file") MultipartFile file, Principal principal) throws Exception {
        if (principal == null) throw new AccessDeniedException("login required");
        if (file.getSize() > MAX_SIZE) throw new IllegalArgumentException();
        String type = tika.detect(file.getInputStream());
        if (!ALLOWED.contains(type)) throw new IllegalArgumentException();
        file.transferTo(Paths.get("/data", UUID.randomUUID().toString()));
        return type;
    }

    // a central SecurityFilterChain elsewhere and an injected principal: auth-unobserved, never a fail.
    // ruleid: upload-validation.java-spring.handler
    // ruleid: upload-validation.java-spring.auth-unobserved
    // ok: upload-validation.java-spring.no-size-limit
    // ok: upload-validation.java-spring.no-content-type-check
    @PostMapping("/files")
    String j1(@RequestPart("file") MultipartFile file, @AuthenticationPrincipal UserDetails user) throws Exception {
        if (file.getSize() > MAX_SIZE) throw new IllegalArgumentException();
        String type = tika.detect(file.getInputStream());
        if (!ALLOWED.contains(type)) throw new IllegalArgumentException();
        file.transferTo(Paths.get("/data", UUID.randomUUID().toString()));
        return user.getUsername();
    }

    // A reversed size check and a type check through a helper are candidates; a bound scan result tested
    // with instanceof VirusFound is the control.
    // ok: upload-validation.java-spring.handler
    // ruleid: upload-validation.java-spring.size-candidate
    // ok: upload-validation.java-spring.no-size-limit
    // ruleid: upload-validation.java-spring.type-candidate
    // ok: upload-validation.java-spring.no-content-type-check
    @Secured("ROLE_CLINICIAN")
    String candidates(@RequestPart("file") MultipartFile file) throws Exception {
        if (MAX_SIZE < file.getSize()) throw new IllegalArgumentException();
        String type = tika.detect(file.getInputStream());
        if (!isAllowedType(type)) throw new IllegalArgumentException();
        // ruleid: upload-validation.java-spring.scan-candidate
        ScanResult result = clamavClient.scan(file.getInputStream());
        if (result instanceof ScanResult.VirusFound) throw new IllegalStateException();
        file.transferTo(Paths.get("/data", UUID.randomUUID().toString()));
        return type;
    }
}

// ---- More cases.
@RestController
class Round5UploadController {
    // a file-count check isn't a size limit (an upper bound on a length: a candidate).
    // ruleid: upload-validation.java-spring.size-candidate
    // ok: upload-validation.java-spring.no-size-limit
    @PreAuthorize("isAuthenticated()")
    @PostMapping("/j1")
    public void upload(@RequestParam("f") MultipartFile[] files) throws Exception {
        if (files.length > MAX_FILES) throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        MultipartFile file = files[0];
        String type = tika.detect(file.getInputStream());
        if (!ALLOWED.contains(type)) throw new ResponseStatusException(HttpStatus.UNSUPPORTED_MEDIA_TYPE);
        // ruleid: upload-validation.java-spring.scan-candidate
        ScanResult res = clamav.scan(file.getInputStream());
        if (res instanceof ScanResult.VirusFound) throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY);
        s3.putObject("phi", UUID.randomUUID().toString(), file.getInputStream(), null);
    }

    // The file's own bytes are its size; a scan whose verdict isn't read canonically is scan-unchecked.
    // ruleid: upload-validation.java-spring.scan-unchecked
    // ruleid: upload-validation.java-spring.handler
    // ok: upload-validation.java-spring.no-size-limit
    // ok: upload-validation.java-spring.size-candidate
    @PreAuthorize("isAuthenticated()")
    @PostMapping("/j2")
    public void upload2(@RequestParam("f") MultipartFile file) throws Exception {
        if (file.getBytes().length > MAX_SIZE) throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE);
        String type = tika.detect(file.getInputStream());
        if (!ALLOWED.contains(type)) throw new ResponseStatusException(HttpStatus.UNSUPPORTED_MEDIA_TYPE);
        // ruleid: upload-validation.java-spring.scan-candidate
        Object res = clamav.scan(file.getInputStream());
        if (res == null) throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY);
        s3.putObject("phi", UUID.randomUUID().toString(), file.getInputStream(), null);
    }
}
