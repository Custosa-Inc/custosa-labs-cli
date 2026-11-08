# Made-up upload views. A control counts only in a canonical, fully bound shape in the view's own
# scope; a shape that only resembles one is evidence (type-candidate, size-candidate, auth-unobserved), leaving the
# view needs_review; a violation fires only when the absence is visible in this file.
from fastapi import FastAPI, APIRouter, Depends, UploadFile
from flask import Flask, request

app = Flask(__name__)
api = FastAPI()
router = APIRouter()


@login_required
# ok: upload-validation.python-fastapi.handler
# ok: upload-validation.python-fastapi.no-content-type-check
# ok: upload-validation.python-fastapi.type-candidate
# ok: upload-validation.python-fastapi.no-size-limit
# ok: upload-validation.python-fastapi.size-candidate
# ok: upload-validation.python-fastapi.no-authorization
# ok: upload-validation.python-fastapi.auth-unobserved
# ok: upload-validation.python-fastapi.scan-unchecked
def upload(request):
    f = request.FILES["file"]
    if f.size > MAX_UPLOAD_BYTES:
        return HttpResponse(status=413)
    kind = magic.from_buffer(f.read(2048), mime=True)
    if kind not in ALLOWED:
        return HttpResponse(status=415)
    # ruleid: upload-validation.python-fastapi.scan-candidate
    if not clamd.scan_stream(f.read()).is_clean:
        return HttpResponse(status=422)
    key = str(uuid.uuid4())
    # ok: upload-validation.python-fastapi.original-name-key
    storage.save(key, f)
    return JsonResponse({"key": key})


# The scan only logged, the type computed and ignored, the size only read, the client's name kept.
# A plain view (Django) has no route visible here, so missing auth is unobserved, not a fail.
# ruleid: upload-validation.python-fastapi.handler
# ruleid: upload-validation.python-fastapi.no-content-type-check
# ruleid: upload-validation.python-fastapi.no-size-limit
# ruleid: upload-validation.python-fastapi.auth-unobserved
# ok: upload-validation.python-fastapi.no-authorization
def upload_record(request):
    f = request.FILES["file"]
    # ok: upload-validation.python-fastapi.scan-candidate
    logger.info("virus scan skipped")
    kind = magic.from_buffer(f.read(2048), mime=True)
    size = f.size
    # ruleid: upload-validation.python-fastapi.original-name-key
    default_storage.save(f"patients/{f.name}", f)
    return JsonResponse({"ok": True})


# A Flask view on the app created in this file, its only decorator the route, no before_request hook, no
# auth read: the absence is visible.
@app.route("/upload", methods=["POST"])
# ruleid: upload-validation.python-fastapi.handler
# ruleid: upload-validation.python-fastapi.no-authorization
# ok: upload-validation.python-fastapi.auth-unobserved
# ok: upload-validation.python-fastapi.no-size-limit
# ok: upload-validation.python-fastapi.no-content-type-check
def flask_upload():
    data = request.files["file"].read()
    if len(data) > 5_000_000:
        abort(413)
    kind = magic.from_buffer(data[:2048], mime=True)
    if kind not in ALLOWED:
        abort(415)
    storage.save(str(uuid.uuid4()), data)


# FastAPI with the canonical current-user dependency, a bound clamd verdict and a filetype mime check.
@api.post("/files")
# ok: upload-validation.python-fastapi.handler
# ok: upload-validation.python-fastapi.no-authorization
# ok: upload-validation.python-fastapi.auth-unobserved
# ok: upload-validation.python-fastapi.no-content-type-check
# ok: upload-validation.python-fastapi.size-candidate
def api_upload(file: UploadFile, user=Depends(get_current_user)):
    data = file.file.read()
    if file.size > MAX_UPLOAD_BYTES:
        raise HTTPException(413)
    kind = filetype.guess(data)
    if kind is None or kind.mime not in ALLOWED:
        raise HTTPException(415)
    # ruleid: upload-validation.python-fastapi.scan-candidate
    result = clamd_client.instream(io.BytesIO(data))
    if result["stream"][0] == "FOUND":
        raise HTTPException(422)
    storage.save(str(uuid.uuid4()), data)


# Depends on a name that isn't a current-user dependency is auth evidence only (auth-unobserved), and
# a router (not the app) can carry dependencies where it is included: never a fail.
@router.post("/files2")
# ruleid: upload-validation.python-fastapi.handler
# ruleid: upload-validation.python-fastapi.auth-unobserved
# ok: upload-validation.python-fastapi.no-authorization
def api_upload2(file: UploadFile, token=Depends(get_token_header)):
    data = file.file.read()
    if file.size > MAX_UPLOAD_BYTES:
        raise HTTPException(413)
    kind = filetype.guess(data)
    if kind is None or kind.mime not in ALLOWED:
        raise HTTPException(415)
    storage.save(str(uuid.uuid4()), data)


# The clamd result only checked for existence; a type check through a helper; a reversed size check.
@login_required
# ruleid: upload-validation.python-fastapi.handler
# ruleid: upload-validation.python-fastapi.type-candidate
# ok: upload-validation.python-fastapi.no-content-type-check
# ruleid: upload-validation.python-fastapi.size-candidate
# ok: upload-validation.python-fastapi.no-size-limit
# ruleid: upload-validation.python-fastapi.scan-unchecked
def upload_candidates(request):
    f = request.FILES["file"]
    if MAX_UPLOAD_BYTES < f.size:
        return HttpResponse(status=413)
    kind = magic.from_buffer(f.read(2048), mime=True)
    if not is_allowed_type(kind):
        return HttpResponse(status=415)
    # ruleid: upload-validation.python-fastapi.scan-candidate
    r = clamd.scan_stream(f.read())
    if not r:
        return HttpResponse(status=500)
    storage.save(str(uuid.uuid4()), f)


# A limit held in settings is a size candidate, never a fail.
@login_required
# ruleid: upload-validation.python-fastapi.handler
# ruleid: upload-validation.python-fastapi.size-candidate
# ok: upload-validation.python-fastapi.no-size-limit
def upload_settings(request):
    f = request.FILES["file"]
    if f.size > settings.MAX_UPLOAD_SIZE:
        return HttpResponse(status=413)
    kind = magic.from_buffer(f.read(2048), mime=True)
    if kind not in ALLOWED:
        return HttpResponse(status=415)
    storage.save(str(uuid.uuid4()), f)


# A medical scan saved inside an if is no malware scan.
@login_required
# ruleid: upload-validation.python-fastapi.handler
# ruleid: upload-validation.python-fastapi.scan-unchecked
def upload_xray(request):
    f = request.files["file"]
    if f.size > MAX_UPLOAD_BYTES:
        return HttpResponse(status=413)
    kind = magic.from_buffer(f.read(2048), mime=True)
    if kind not in ALLOWED:
        return HttpResponse(status=415)
    if request.form.get("patient_id"):
        # ruleid: upload-validation.python-fastapi.scan-candidate
        save_xray_scan(str(uuid.uuid4()), f)
    return JsonResponse({})


# More cases.
# A Celery scan task queued after saving, and an is_safe_url redirect check: no verdict gates the upload.
@login_required
# ruleid: upload-validation.python-fastapi.handler
# ok: upload-validation.python-fastapi.no-content-type-check
# ok: upload-validation.python-fastapi.no-size-limit
# ok: upload-validation.python-fastapi.no-authorization
# ruleid: upload-validation.python-fastapi.scan-unchecked
def upload(request):
    f = request.FILES["file"]
    if f.size > MAX_UPLOAD_BYTES:
        return HttpResponse(status=413)
    kind = magic.from_buffer(f.read(2048), mime=True)
    if kind not in ALLOWED:
        return HttpResponse(status=415)
    key = str(uuid.uuid4())
    # ok: upload-validation.python-fastapi.original-name-key
    storage.save(key, f)
    # ruleid: upload-validation.python-fastapi.scan-candidate
    scan_for_viruses.delay(key)
    nxt = request.GET.get("next")
    if not is_safe_url(nxt):
        nxt = "/"
    return redirect(nxt)


# A size check whose only abort is a comment.
@login_required
# ok: upload-validation.python-fastapi.handler
# ruleid: upload-validation.python-fastapi.no-size-limit
# ok: upload-validation.python-fastapi.no-content-type-check
# ok: upload-validation.python-fastapi.no-authorization
def upload2(request):
    f = request.FILES["file"]
    if f.size > MAX_UPLOAD_BYTES:
        # TODO: return HttpResponse(status=413)
        logger.warning("big")
    kind = magic.from_buffer(f.read(2048), mime=True)
    if kind not in ALLOWED:
        return HttpResponse(status=415)
    # ruleid: upload-validation.python-fastapi.scan-candidate
    if not clamd.scan_stream(f.read()).is_clean:
        return HttpResponse(status=422)
    # ok: upload-validation.python-fastapi.original-name-key
    storage.save(str(uuid.uuid4()), f)


# ---- More cases. Each app has its own name, so its app-level hooks bind only its routes.
app_y2 = Flask(__name__)


# a file-count check isn't a size limit (an upper bound on a length: a candidate).
@app_y2.route("/y2", methods=["POST"])
@login_required
# ok: upload-validation.python-fastapi.no-size-limit
# ruleid: upload-validation.python-fastapi.size-candidate
def upload_y2():
    files = request.files.getlist("f")
    if len(files) > MAX_FILES:
        abort(400)
    data = files[0].read()
    kind = magic.from_buffer(data, mime=True)
    if kind not in ALLOWED:
        abort(415)
    # ruleid: upload-validation.python-fastapi.scan-candidate
    result = cd.instream(io.BytesIO(data))
    if result["stream"][0] == "FOUND":
        abort(422)
    s3.put_object(Bucket="phi", Key=str(uuid4()), Body=data)


app_y1 = FastAPI()


@app_y1.middleware("http")
async def require_login(request: Request, call_next):
    if not request.headers.get("authorization"):
        return JSONResponse(status_code=401, content={})
    return await call_next(request)


# an app-level http middleware may do the auth: auth unobserved, never no-authorization.
@app_y1.post("/y1")
# ok: upload-validation.python-fastapi.no-authorization
# ruleid: upload-validation.python-fastapi.auth-unobserved
def upload_y1(file: UploadFile):
    data = file.file.read()
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413)
    kind = magic.from_buffer(data, mime=True)
    if kind not in ALLOWED:
        raise HTTPException(415)
    # ruleid: upload-validation.python-fastapi.scan-candidate
    result = cd.instream(io.BytesIO(data))
    if result["stream"][0] == "FOUND":
        raise HTTPException(422)
    s3.put_object(Bucket="phi", Key=str(uuid4()), Body=data)


app_y3 = FastAPI(middleware=[Middleware(AuthenticationMiddleware, backend=JWTBackend())])


# auth middleware passed to the FastAPI constructor: auth unobserved.
@app_y3.post("/y3")
# ok: upload-validation.python-fastapi.no-authorization
# ruleid: upload-validation.python-fastapi.auth-unobserved
# ruleid: upload-validation.python-fastapi.handler
def upload_y3(file: UploadFile):
    data = file.file.read()
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413)
    kind = magic.from_buffer(data, mime=True)
    if kind not in ALLOWED:
        raise HTTPException(415)
    s3.put_object(Bucket="phi", Key=str(uuid4()), Body=data)


app_y4 = Flask(__name__)
setup_auth(app_y4)


# A call that takes the app may install auth: auth unobserved.
@app_y4.route("/y4", methods=["POST"])
# ok: upload-validation.python-fastapi.no-authorization
# ruleid: upload-validation.python-fastapi.auth-unobserved
# ruleid: upload-validation.python-fastapi.handler
def upload_y4():
    data = request.files["file"].read()
    if len(data) > 5_000_000:
        abort(413)
    kind = magic.from_buffer(data, mime=True)
    if kind not in ALLOWED:
        abort(415)
    s3.put_object(Bucket="phi", Key=str(uuid4()), Body=data)


app_y5 = Flask(__name__)
CORS(app_y5)
db.init_app(app_y5)


# Only known-benign calls take the app: the absence of auth stays visible. A len() on a name not read from the upload
# is only a candidate.
@app_y5.route("/y5", methods=["POST"])
# ok: upload-validation.python-fastapi.auth-unobserved
# ok: upload-validation.python-fastapi.no-size-limit
# ruleid: upload-validation.python-fastapi.no-authorization
# ruleid: upload-validation.python-fastapi.size-candidate
# ruleid: upload-validation.python-fastapi.handler
def upload_y5():
    names = request.form.getlist("names")
    if len(names) > MAX_NAMES:
        abort(400)
    data = request.files["file"].read()
    kind = magic.from_buffer(data, mime=True)
    if kind not in ALLOWED:
        abort(415)
    s3.put_object(Bucket="phi", Key=str(uuid4()), Body=data)


# A scan whose verdict isn't read canonically, in the view's own scope: scan-unchecked.
@app_y2.route("/y6", methods=["POST"])
@login_required
# ruleid: upload-validation.python-fastapi.scan-unchecked
# ruleid: upload-validation.python-fastapi.handler
def upload_y6():
    data = request.files["file"].read()
    if len(data) > 5_000_000:
        abort(413)
    kind = magic.from_buffer(data, mime=True)
    if kind not in ALLOWED:
        abort(415)
    # ruleid: upload-validation.python-fastapi.scan-candidate
    reply = cd.instream(io.BytesIO(data))
    if "FOUND" in str(reply):
        abort(422)
    s3.put_object(Bucket="phi", Key=str(uuid4()), Body=data)
