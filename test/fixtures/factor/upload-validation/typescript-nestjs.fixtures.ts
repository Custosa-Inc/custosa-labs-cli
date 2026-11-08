// Made-up upload handlers. A control counts only in a canonical, fully bound shape in the handler's
// own scope; a shape that only resembles one is evidence (type-candidate, size-candidate, auth-unobserved), which
// leaves the handler needs_review; a violation fires only when the absence is visible in this file.
import express from "express";
import multer from "multer";
const app = express();
const upload = multer({ dest: "/tmp/uploads" });

// Every check enforced, the scan checked before the key is written.
// ok: upload-validation.typescript-nestjs.handler
// ok: upload-validation.typescript-nestjs.no-content-type-check
// ok: upload-validation.typescript-nestjs.type-candidate
// ok: upload-validation.typescript-nestjs.no-size-limit
// ok: upload-validation.typescript-nestjs.size-candidate
// ok: upload-validation.typescript-nestjs.no-authorization
// ok: upload-validation.typescript-nestjs.auth-unobserved
// ok: upload-validation.typescript-nestjs.scan-unchecked
export async function POST(request) {
  const session = await getServerSession();
  if (!session) return new Response("unauthorized", { status: 401 });
  const form = await request.formData();
  const file = form.get("file");
  if (file.size > MAX_UPLOAD_BYTES) return new Response("too large", { status: 413 });
  const type = await fileTypeFromBuffer(new Uint8Array(await file.arrayBuffer()));
  if (!type || !ALLOWED.includes(type.mime)) return new Response("type", { status: 415 });
  // ruleid: upload-validation.typescript-nestjs.scan-candidate
  const verdict = await clamscan.scanBuffer(Buffer.from(await file.arrayBuffer()));
  if (verdict.isInfected) return new Response("infected", { status: 422 });
  const key = crypto.randomUUID();
  // ok: upload-validation.typescript-nestjs.original-name-key
  await supabase.storage.from("docs").upload(key, file);
  return Response.json({ key });
}

// No auth, the scan only logged, the sniffed type ignored, the size only read, the client's name as
// key. The route call, the app and its multer instance (no limits) are all in this file: every absence is visible.
// ruleid: upload-validation.typescript-nestjs.handler
// ruleid: upload-validation.typescript-nestjs.no-content-type-check
// ruleid: upload-validation.typescript-nestjs.no-size-limit
// ruleid: upload-validation.typescript-nestjs.no-authorization
app.post("/upload", upload.single("file"), async (req, res) => {
  const file = req.file;
  // ok: upload-validation.typescript-nestjs.scan-candidate
  console.log("TODO: virus scan not wired up");
  const sniffed = await fileTypeFromBuffer(file.buffer);
  const fileSize = file.size;
  // ruleid: upload-validation.typescript-nestjs.original-name-key
  const key = `patients/${file.originalname}`;
  await s3.send(new PutObjectCommand({ Bucket: "phi", Key: key, Body: file.buffer }));
  res.json({ ok: true, name: file.originalname });
});

// A "scan" flag set to false is no scan; a size compared with 0 limits nothing (no rejection).
// ruleid: upload-validation.typescript-nestjs.handler
// ruleid: upload-validation.typescript-nestjs.no-content-type-check
// ruleid: upload-validation.typescript-nestjs.no-size-limit
// ruleid: upload-validation.typescript-nestjs.no-authorization
app.post("/upload2", upload.single("file"), async (req, res) => {
  const scanUpload = false;
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (req.file.size > 0) {}
  await s3.send(new PutObjectCommand({ Bucket: "phi", Key: randomUUID(), Body: req.file.buffer }));
});

// clamp is no ClamAV; the route's auth middleware is the authorization.
// ruleid: upload-validation.typescript-nestjs.handler
// ruleid: upload-validation.typescript-nestjs.no-content-type-check
// ruleid: upload-validation.typescript-nestjs.no-size-limit
// ok: upload-validation.typescript-nestjs.no-authorization
// ok: upload-validation.typescript-nestjs.auth-unobserved
app.post("/avatar", requireAuth, upload.single("file"), async (req, res) => {
  const width = clamp(req.body.width, 16, 512);
  const t = await fileTypeFromBuffer(req.file.buffer);
  const MAX_UPLOAD_BYTES = 10;
  await s3.send(new PutObjectCommand({ Bucket: "phi", Key: randomUUID(), Body: req.file.buffer }));
});

// A function that takes no upload is no upload handler.
// ok: upload-validation.typescript-nestjs.handler
// ok: upload-validation.typescript-nestjs.no-authorization
// ok: upload-validation.typescript-nestjs.auth-unobserved
function listFiles(req, res) {
  res.json([]);
}

// A named handler. Its route call isn't visible here, so a missing auth check is unobserved, not absent.
// ruleid: upload-validation.typescript-nestjs.handler
// ruleid: upload-validation.typescript-nestjs.auth-unobserved
// ok: upload-validation.typescript-nestjs.no-authorization
// ok: upload-validation.typescript-nestjs.no-size-limit
// ok: upload-validation.typescript-nestjs.no-content-type-check
async function namedUpload(req, res) {
  if (req.file.size > MAX_UPLOAD_BYTES) return res.status(413).end();
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (!ALLOWED.has(t.mime)) return res.status(415).end();
  await s3.send(new PutObjectCommand({ Bucket: "phi", Key: randomUUID(), Body: req.file.buffer }));
}

// The route's multer instance is imported, so its limits can't be read here: a size candidate, not a fail.
// ruleid: upload-validation.typescript-nestjs.handler
// ruleid: upload-validation.typescript-nestjs.size-candidate
// ok: upload-validation.typescript-nestjs.no-size-limit
// ok: upload-validation.typescript-nestjs.no-authorization
app.post("/imported", requireAuth, sharedUpload.single("file"), async (req, res) => {
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (!t || !ALLOWED.includes(t.mime)) return res.status(415).end();
  await s3.send(new PutObjectCommand({ Bucket: "phi", Key: randomUUID(), Body: req.file.buffer }));
});

// a type check through a helper is a type candidate, never a fail and never the control.
// ruleid: upload-validation.typescript-nestjs.handler
// ruleid: upload-validation.typescript-nestjs.type-candidate
// ok: upload-validation.typescript-nestjs.no-content-type-check
app.post("/u10", requireAuth, upload.single("file"), async (req, res) => {
  if (req.file.size > MAX_UPLOAD_BYTES) return res.status(413).end();
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (!isAllowedType(t)) return res.status(415).end();
  await s3.send(new PutObjectCommand({ Bucket: "phi", Key: randomUUID(), Body: req.file.buffer }));
});

// ---- More cases. Each app below has its own name, so its app-level middleware binds only
// the routes on that app.
const app5 = express();
app5.use(express.json());
app5.use(isLoggedIn);
const upload5 = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5_000_000 } });

// a global app5.use(isLoggedIn) may protect every route: auth unobserved, never no-authorization.
// ok: upload-validation.typescript-nestjs.no-authorization
// ruleid: upload-validation.typescript-nestjs.auth-unobserved
app5.post("/a1", upload5.single("file"), async (req, res) => {
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (!t || !ALLOWED.includes(t.mime)) return res.status(415).end();
  // ruleid: upload-validation.typescript-nestjs.scan-candidate
  const v = await clamscan.scanBuffer(req.file.buffer);
  if (v.isInfected) return res.status(422).end();
  await s3.send(new PutObjectCommand({ Bucket: "phi", Key: randomUUID(), Body: req.file.buffer }));
});

// a file-count check isn't a size limit (only a candidate: an upper bound on a length).
// ok: upload-validation.typescript-nestjs.no-size-limit
// ruleid: upload-validation.typescript-nestjs.size-candidate
app5.post("/a4", requireAuth, multer({ storage: multer.memoryStorage() }).array("files"), async (req, res) => {
  if (req.files.length > MAX_FILES) return res.status(400).end();
  for (const f of req.files) {
    const t = await fileTypeFromBuffer(f.buffer);
    if (!t || !ALLOWED.includes(t.mime)) return res.status(415).end();
  }
  // ruleid: upload-validation.typescript-nestjs.scan-candidate
  const v = await clamscan.scanBuffer(req.files[0].buffer);
  if (v.isInfected) return res.status(422).end();
  await s3.send(new PutObjectCommand({ Bucket: "phi", Key: randomUUID(), Body: req.files[0].buffer }));
});

// a daily-quota count isn't a size limit (candidate).
// ok: upload-validation.typescript-nestjs.no-size-limit
// ruleid: upload-validation.typescript-nestjs.size-candidate
app5.post("/a5", requireAuth, multer({ storage: multer.memoryStorage() }).single("file"), async (req, res) => {
  const today = await db.uploadsToday(req.user.id);
  if (today.length > MAX_DAILY_UPLOADS) return res.status(429).end();
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (!t || !ALLOWED.includes(t.mime)) return res.status(415).end();
  // ruleid: upload-validation.typescript-nestjs.scan-candidate
  const v = await clamscan.scanBuffer(req.file.buffer);
  if (v.isInfected) return res.status(422).end();
  await s3.send(new PutObjectCommand({ Bucket: "phi", Key: randomUUID(), Body: req.file.buffer }));
});

// a filename length isn't a size limit (candidate).
// ok: upload-validation.typescript-nestjs.no-size-limit
// ruleid: upload-validation.typescript-nestjs.size-candidate
app5.post("/a6", requireAuth, multer({ storage: multer.memoryStorage() }).single("file"), async (req, res) => {
  if (req.file.originalname.length > MAX_NAME_LENGTH) return res.status(400).end();
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (!t || !ALLOWED.includes(t.mime)) return res.status(415).end();
  // ruleid: upload-validation.typescript-nestjs.scan-candidate
  const v = await clamscan.scanBuffer(req.file.buffer);
  if (v.isInfected) return res.status(422).end();
  await s3.send(new PutObjectCommand({ Bucket: "phi", Key: randomUUID(), Body: req.file.buffer }));
});

// fileSize: Infinity is visibly no limit: no-size-limit, not a candidate.
// ok: upload-validation.typescript-nestjs.size-candidate
// ruleid: upload-validation.typescript-nestjs.no-size-limit
app5.post("/a7", requireAuth, multer({ limits: { fileSize: Infinity } }).single("file"), async (req, res) => {
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (!t || !ALLOWED.includes(t.mime)) return res.status(415).end();
  // ruleid: upload-validation.typescript-nestjs.scan-candidate
  const v = await clamscan.scanBuffer(req.file.buffer);
  if (v.isInfected) return res.status(422).end();
  await s3.send(new PutObjectCommand({ Bucket: "phi", Key: randomUUID(), Body: req.file.buffer }));
});

// a 401 set without a return doesn't end the handler, so it isn't the guard: auth unobserved (an auth read).
// ruleid: upload-validation.typescript-nestjs.auth-unobserved
app5.post("/a8", upload5.single("file"), async (req, res) => {
  if (!req.user) { res.status(401).json({ error: "login" }); }
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (!t || !ALLOWED.includes(t.mime)) return res.status(415).end();
  // ruleid: upload-validation.typescript-nestjs.scan-candidate
  const v = await clamscan.scanBuffer(req.file.buffer);
  if (v.isInfected) return res.status(422).end();
  await s3.send(new PutObjectCommand({ Bucket: "phi", Key: randomUUID(), Body: req.file.buffer }));
});

// an empty-file check is no upper bound: no-size-limit stays.
// ok: upload-validation.typescript-nestjs.size-candidate
// ruleid: upload-validation.typescript-nestjs.no-size-limit
app5.post("/a9", requireAuth, multer({ storage: multer.memoryStorage() }).single("file"), async (req, res) => {
  if (!req.file || req.file.buffer.length === 0) return res.status(400).end();
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (!t || !ALLOWED.includes(t.mime)) return res.status(415).end();
  // ruleid: upload-validation.typescript-nestjs.scan-candidate
  const v = await clamscan.scanBuffer(req.file.buffer);
  if (v.isInfected) return res.status(422).end();
  await s3.send(new PutObjectCommand({ Bucket: "phi", Key: randomUUID(), Body: req.file.buffer }));
});

// fully canonical, nothing else in scope.
// ok: upload-validation.typescript-nestjs.handler
// ok: upload-validation.typescript-nestjs.scan-unchecked
app5.post("/a10", requireAuth, upload5.single("file"), async (req, res) => {
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (!t || !ALLOWED.includes(t.mime)) return res.status(415).end();
  // ruleid: upload-validation.typescript-nestjs.scan-candidate
  const v = await clamscan.scanBuffer(req.file.buffer);
  if (v.isInfected) return res.status(422).end();
  await s3.send(new PutObjectCommand({ Bucket: "phi", Key: randomUUID(), Body: req.file.buffer }));
});

// a short receiver's instream call is a scan-candidate; its verdict isn't canonical, so the handler also
// carries scan-unchecked.
// ruleid: upload-validation.typescript-nestjs.scan-unchecked
// ruleid: upload-validation.typescript-nestjs.handler
app5.post("/a11", requireAuth, upload5.single("file"), async (req, res) => {
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (!t || !ALLOWED.includes(t.mime)) return res.status(415).end();
  // ruleid: upload-validation.typescript-nestjs.scan-candidate
  const reply = await cd.instream(Readable.from(req.file.buffer));
  if (reply.includes("FOUND")) return res.status(422).end();
  await s3.send(new PutObjectCommand({ Bucket: "phi", Key: randomUUID(), Body: req.file.buffer }));
});

// vendor scanners (cloudmersive, opswat) are scan-candidates; the verdict isn't canonical: scan-unchecked.
// ruleid: upload-validation.typescript-nestjs.scan-unchecked
// ruleid: upload-validation.typescript-nestjs.handler
app5.post("/a12", requireAuth, upload5.single("file"), async (req, res) => {
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (!t || !ALLOWED.includes(t.mime)) return res.status(415).end();
  // ruleid: upload-validation.typescript-nestjs.scan-candidate
  const { foundViruses } = await cloudmersiveApi.virusScanFileAdvanced(req.file.buffer);
  // ruleid: upload-validation.typescript-nestjs.scan-candidate
  const r = await opswat.processFile(req.file.buffer);
  if (r.scan_results.scan_all_result_a !== "No Threat Detected") return res.status(422).end();
  await s3.send(new PutObjectCommand({ Bucket: "phi", Key: randomUUID(), Body: req.file.buffer }));
});

// A queue flag in the arguments doesn't drop the scan-candidate; the exclusion reads the callee only.
// ruleid: upload-validation.typescript-nestjs.scan-unchecked
// ruleid: upload-validation.typescript-nestjs.handler
app5.post("/a13", requireAuth, upload5.single("file"), async (req, res) => {
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (!t || !ALLOWED.includes(t.mime)) return res.status(415).end();
  // ruleid: upload-validation.typescript-nestjs.scan-candidate
  const v = await clamscan.scanBuffer(req.file.buffer, { queue: true });
  if (v.ok) return res.status(422).end();
});

// A queue callee is never a scan-candidate.
// ruleid: upload-validation.typescript-nestjs.handler
app5.post("/a14", requireAuth, upload5.single("file"), async (req, res) => {
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (!t || !ALLOWED.includes(t.mime)) return res.status(415).end();
  // ok: upload-validation.typescript-nestjs.scan-candidate
  await malwareScanQueue.add({ key: req.file.filename });
});

const app6 = express();
setupAuth(app6);
const upload6 = multer({ limits: { fileSize: 5_000_000 } });
// auth installed through a helper that receives the app: auth unobserved.
// ok: upload-validation.typescript-nestjs.no-authorization
// ruleid: upload-validation.typescript-nestjs.auth-unobserved
// ruleid: upload-validation.typescript-nestjs.handler
app6.post("/b2", upload6.single("file"), async (req, res) => {
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (!t || !ALLOWED.includes(t.mime)) return res.status(415).end();
  await s3.send(new PutObjectCommand({ Bucket: "phi", Key: randomUUID(), Body: req.file.buffer }));
});

const app7 = express();
app7.all("/api/*", requireAuth);
// an app.all guard: auth unobserved.
// ok: upload-validation.typescript-nestjs.no-authorization
// ruleid: upload-validation.typescript-nestjs.auth-unobserved
// ruleid: upload-validation.typescript-nestjs.handler
app7.post("/api/b3", upload6.single("file"), async (req, res) => {
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (!t || !ALLOWED.includes(t.mime)) return res.status(415).end();
  await s3.send(new PutObjectCommand({ Bucket: "phi", Key: randomUUID(), Body: req.file.buffer }));
});

const app8 = express();
app8.use(express.json(), cors(), helmet());
http.createServer(app8).listen(3000);
const upload8 = multer({ storage: multer.memoryStorage(), limits: { files: 1 /* TODO fileSize: 5_000_000 */ } });
// Only known-benign app middleware and the server wrapper: the absence of auth is still visible.
// ok: upload-validation.typescript-nestjs.auth-unobserved
// ruleid: upload-validation.typescript-nestjs.no-authorization
// ruleid: upload-validation.typescript-nestjs.no-size-limit
// ruleid: upload-validation.typescript-nestjs.handler
app8.post("/b8", upload8.single("file"), async (req, res) => {
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (!t || !ALLOWED.includes(t.mime)) return res.status(415).end();
  await s3.send(new PutObjectCommand({ Bucket: "phi", Key: randomUUID(), Body: req.file.buffer }));
});

// the only fileSize is a comment inside the declared multer limits: no-size-limit.
// ruleid: upload-validation.typescript-nestjs.no-size-limit
app8.post("/c1", requireAuth, upload8.single("file"), async (req, res) => {
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (!t || !ALLOWED.includes(t.mime)) return res.status(415).end();
  // ruleid: upload-validation.typescript-nestjs.scan-candidate
  const v = await clamscan.scanBuffer(req.file.buffer);
  if (v.isInfected) return res.status(422).end();
  await s3.send(new PutObjectCommand({ Bucket: "phi", Key: randomUUID(), Body: req.file.buffer }));
});

// the same, inline in the route call.
// ruleid: upload-validation.typescript-nestjs.no-size-limit
app8.post("/c2", requireAuth, multer({ limits: { files: 1, /* fileSize: 1e6 */ } }).single("file"), async (req, res) => {
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (!t || !ALLOWED.includes(t.mime)) return res.status(415).end();
  // ruleid: upload-validation.typescript-nestjs.scan-candidate
  const v = await clamscan.scanBuffer(req.file.buffer);
  if (v.isInfected) return res.status(422).end();
  await s3.send(new PutObjectCommand({ Bucket: "phi", Key: randomUUID(), Body: req.file.buffer }));
});

// a string holding the text.
// ruleid: upload-validation.typescript-nestjs.no-size-limit
app8.post("/c3", requireAuth, multer({ limits: { files: 1 }, note: "limits: { fileSize: 1 }" }).single("file"), async (req, res) => {
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (!t || !ALLOWED.includes(t.mime)) return res.status(415).end();
  // ruleid: upload-validation.typescript-nestjs.scan-candidate
  const v = await clamscan.scanBuffer(req.file.buffer);
  if (v.isInfected) return res.status(422).end();
  await s3.send(new PutObjectCommand({ Bucket: "phi", Key: randomUUID(), Body: req.file.buffer }));
});

// A fileSize read from config is a size-candidate, not the control and not a fail.
// ok: upload-validation.typescript-nestjs.no-size-limit
// ruleid: upload-validation.typescript-nestjs.size-candidate
app8.post("/c4", requireAuth, multer({ limits: { fileSize: config.maxUploadBytes } }).single("file"), async (req, res) => {
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (!t || !ALLOWED.includes(t.mime)) return res.status(415).end();
  // ruleid: upload-validation.typescript-nestjs.scan-candidate
  const v = await clamscan.scanBuffer(req.file.buffer);
  if (v.isInfected) return res.status(422).end();
});

// a busboy handler whose scan sits in the nested "file" callback: that scan-candidate has no handler,
// and the handler carries no scan-unchecked (the scan isn't in its own scope).
// ok: upload-validation.typescript-nestjs.scan-unchecked
// ruleid: upload-validation.typescript-nestjs.no-content-type-check
// ruleid: upload-validation.typescript-nestjs.handler
app8.post("/bb", requireAuth, (req, res) => {
  const bb = busboy({ headers: req.headers, limits: { fileSize: 5_000_000 } });
  bb.on("file", async (name, file, info) => {
    // ruleid: upload-validation.typescript-nestjs.scan-candidate
    const v = await clamscan.scanStream(file);
    if (v.isInfected) return res.status(422).end();
    await s3.send(new PutObjectCommand({ Bucket: "phi", Key: randomUUID(), Body: file }));
  });
  req.pipe(bb);
});

// Raw-body uploads: a handler taking the request that reads the request itself as a stream (req.pipe,
// req.on('data'), or the request handed to a raw-body reader, a stream helper or a store call), with no multipart
// parser. Its own rules: an item (the scan is its control) always held by size-candidate-raw-body (no canonical shape
// settles a stream's checks, so never a pass), and a violation when no type check, or no size check, is in view.
import { handleStoreInstances, handleSearchStudies } from "./stow";
import { upload_attachment } from "./attachments";
import { handleUploadFile } from "./files";
import { updateProfile } from "./profile";
import { downloadFile } from "./download";

// A named raw-body handler: the stream is stored with the client's Content-Type, no sniffed type and no size limit.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
async function handleBinaryWrite(req: Request, res: Response) {
  const stream = getContentStream(req);
  const binary = await uploadBinaryData(repo, stream, { contentType: req.get("Content-Type") });
  res.json(binary);
}
binaryRouter.post("/", handleBinaryWrite);
// The stream reader is declared here (it hands the request back), so nothing the handler calls is out of view.
function getContentStream(req) { return req; }

// A signed-URL PUT: the only type check compares the client's header with the stored one (not content-based), then
// the request stream is written, with no size limit.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
storageRouter.put("/:id", async (req: Request, res: Response) => {
  const binary = await verifyAndLoadBinary(req, res);
  if (!binary) return;
  if (req.headers["content-type"] !== binary.contentType) return res.status(400).send("mismatch");
  await getBinaryStorage().writeBinary(binary, req);
  res.sendStatus(200);
});
async function verifyAndLoadBinary(req, res) { return repo.readBinary(req.params.id); }

// req.pipe into a file stream, req.on('data'), and pipeline(req, ...): raw-body uploads.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/raw-pipe", async (req: Request, res: Response) => {
  req.pipe(fs.createWriteStream(`/tmp/${crypto.randomUUID()}`));
  res.sendStatus(201);
});
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/raw-data", (req: Request, res: Response) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => res.sendStatus(201));
});
// A size limit and a sniffed type in view: no violation, still held (the item never passes).
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/raw-pipeline", async (req: Request, res: Response) => {
  if (Number(req.headers["content-length"]) > MAX_UPLOAD_BYTES) return res.sendStatus(413);
  const buf = await getRawBody(req, { limit: "10mb" });
  const type = await fileTypeFromBuffer(buf);
  if (!type || !ALLOWED.includes(type.mime)) return res.sendStatus(415);
  await pipeline(req, fs.createWriteStream(`/tmp/${crypto.randomUUID()}`));
  res.sendStatus(201);
});

// Not raw-body uploads: the request handed to a logger or a non-stream helper, a stream helper given req.body, and
// req.on for a close event. A busboy handler that pipes the request into the parser is the handler rule's item (above).
// ok: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/not-raw-1", async (req: Request, res: Response) => {
  auditRequest(req);
  saveAudit(req);
  const s = getContentStream(req.body);
  req.on("close", () => s.destroy());
  res.json({ ok: true });
});

// The scan checked in a canonical shape is the item's control; the item is still held, never a pass.
// ok: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
export async function PUT(request) {
  const file = new Blob([await getRawBody(request)]);
  if (file.size > MAX_UPLOAD_BYTES) return new Response("too large", { status: 413 });
  const type = await fileTypeFromBuffer(new Uint8Array(await file.arrayBuffer()));
  if (!type || !ALLOWED.includes(type.mime)) return new Response("type", { status: 415 });
  // ruleid: upload-validation.typescript-nestjs.scan-candidate
  const verdict = await clamscan.scanBuffer(Buffer.from(await file.arrayBuffer()));
  if (verdict.isInfected) return new Response("infected", { status: 422 });
  await store.put(crypto.randomUUID(), file);
  return Response.json({ ok: true });
}

// An upload route whose handler is imported from another file (the DICOM STOW shape): an item held for a person by
// type-candidate-imported, since its type, size, key and scan checks aren't in view. Never a pass, never a fail.
// ruleid: upload-validation.typescript-nestjs.imported-upload
// ruleid: upload-validation.typescript-nestjs.type-candidate-imported
router.post("/studies", handleStoreInstances);
// ruleid: upload-validation.typescript-nestjs.imported-upload
// ruleid: upload-validation.typescript-nestjs.type-candidate-imported
router.post("/studies/:studyUid", authenticate, handleStoreInstances);
// ruleid: upload-validation.typescript-nestjs.imported-upload
// ruleid: upload-validation.typescript-nestjs.type-candidate-imported
router.put("/attachments/:id", upload_attachment);
// A scanning middleware in the route chain is the item's control; the handler is still out of view (held).
// ok: upload-validation.typescript-nestjs.imported-upload
// ruleid: upload-validation.typescript-nestjs.type-candidate-imported
// ruleid: upload-validation.typescript-nestjs.scan-candidate
router.post("/scanned", clamScanMiddleware(), handleUploadFile);
// Not upload-shaped: a search handler, a profile update ("Profile" is not "File"), a GET, a handler declared here, and
// an imported handler followed by an inline one (the inline one is read by the handler rule).
// ok: upload-validation.typescript-nestjs.imported-upload
// ok: upload-validation.typescript-nestjs.type-candidate-imported
router.post("/studies/search", handleSearchStudies);
// ok: upload-validation.typescript-nestjs.imported-upload
// ok: upload-validation.typescript-nestjs.type-candidate-imported
router.post("/profile", updateProfile);
// ok: upload-validation.typescript-nestjs.imported-upload
router.get("/files/:id", downloadFile);
// ok: upload-validation.typescript-nestjs.imported-upload
router.post("/local", uploadLocal);
// ok: upload-validation.typescript-nestjs.imported-upload
// ok: upload-validation.typescript-nestjs.type-candidate-imported
router.post("/chain", handleStoreInstances, async (req: Request, res: Response) => { res.sendStatus(204); });
function uploadLocal(req: Request, res: Response) { res.sendStatus(204); }

// A data URL written to storage (the NestJS lab-result shape): an item held for a person by type-candidate-data-url,
// since the type, size and scan checks may sit in the DTO, a pipe or the controller, in another file.
class LabResults {
  // ruleid: upload-validation.typescript-nestjs.data-url-write
  // ruleid: upload-validation.typescript-nestjs.type-candidate-data-url
  async createResult(dto: CreateResultDto) {
    return this.prisma.labResult.create({ data: { attachmentDataUrl: dto.attachmentDataUrl, attachmentMimeType: dto.mime } });
  }
  // ruleid: upload-validation.typescript-nestjs.data-url-write
  // ruleid: upload-validation.typescript-nestjs.type-candidate-data-url
  async saveScan(body: CreateResultDto) {
    await db.insert({ file_base64: body["file"] });
  }
  // Not a data-URL write: no data-URL field beside a literal one, and a data URL that only goes to a non-write call.
  // ok: upload-validation.typescript-nestjs.data-url-write
  // ok: upload-validation.typescript-nestjs.type-candidate-data-url
  async createNote(dto: CreateResultDto) {
    return this.prisma.note.create({ data: { text: dto.text, dataUrl: "" } });
  }
  // ok: upload-validation.typescript-nestjs.data-url-write
  // ok: upload-validation.typescript-nestjs.type-candidate-data-url
  async preview(dto: CreateResultDto) {
    return JSON.stringify({ dataUrl: dto.dataUrl });
  }
}

// Checks a stream handler commonly uses count, and the handler is held, not failed.
// A stream counter that destroys the request past the bound is a size check.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/f2-counter", async (req: Request, res: Response) => {
  let total = 0;
  req.on("data", (chunk) => { total += chunk.length; if (total > MAX_UPLOAD_BYTES) req.destroy(); });
  const type = await fileTypeFromStream(req);
  req.pipe(out);
});
// The same cut-off without an accumulation: a 413 sent from the data callback.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/f2-cutoff", async (req: Request, res: Response) => {
  req.on("data", (chunk) => { if (tooBig(chunk)) res.status(413).end(); });
  const type = await fileTypeFromStream(req);
  req.pipe(out);
});
// An image decoder's format, and magic-byte compares, are content-based type checks.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/f2-sharp", async (req: Request, res: Response) => {
  const buf = await getRawBody(req, { limit: "5mb" });
  const meta = await sharp(buf).metadata();
  if (!["png", "jpeg"].includes(meta.format)) return res.status(415).end();
  await store.put(randomUUID(), buf);
});
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/f2-magic", async (req: Request, res: Response) => {
  const buf = await getRawBody(req, { limit: "5mb" });
  if (!buf.subarray(0, 4).equals(PNG_MAGIC)) return res.status(415).end();
  await store.put(randomUUID(), buf);
});
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/f2-byte", async (req: Request, res: Response) => {
  const buf = await getRawBody(req, { limit: "5mb" });
  if (buf[0] !== 0x89) return res.status(415).end();
  await store.put(randomUUID(), buf);
});
// The bare request handed to project code (a relative import): its checks are out of view (held, never failed).
import { validateUpload } from "./validate-upload";
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/f2-handoff", async (req: Request, res: Response) => {
  await validateUpload(req);
  req.pipe(out);
});
// A reader helper that hands the request back is still an upload item (never dropped), failing like any other.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
function readStream(req: Request) {
  if (!req.headers["content-encoding"]) return req;
  return req.pipe(zlib.createGunzip());
}
// Still failing: an accumulation with no bound, a header-only type check, and a helper declared in this file.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/f2-unchecked", async (req: Request, res: Response) => {
  let total = 0;
  req.on("data", (chunk) => { total += chunk.length; });
  if (req.headers["content-type"] !== "image/png") return res.status(415).end();
  await localStore(req);
});
async function localStore(stream) { return stream; }

// Holds come only from project code. A package's stream helper, a parameter, a global and a package
// require hold nothing, so these unchecked streams still fail.
import { pipeline as streamPipeline } from "node:stream/promises";
import getRawBodyPkg from "raw-body";
import pumpPkg from "pump";
const { finished } = require("stream");
const { checkUpload } = require("./check-upload");
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/r3-pipeline", async (req: Request, res: Response) => {
  await pipeline(req, fs.createWriteStream(p));
  res.end();
});
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/r3-rawbody", async (req: Request, res: Response) => {
  const buf = await getRawBody(req);
  await s3.putObject({ Key: name, Body: buf });
});
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/r3-pump", (req: Request, res: Response) => {
  pump(req, fs.createWriteStream(p));
});
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/r3-next", (req: Request, res: Response, next) => {
  req.pipe(fs.createWriteStream(p));
  next(req);
});
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/r3-global", (req: Request, res: Response) => {
  audit(req);
  req.pipe(fs.createWriteStream(p));
});
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/r3-require", (req: Request, res: Response) => {
  finished(req, () => res.end());
  req.pipe(fs.createWriteStream(p));
});
// A project helper bound by a relative require holds, like a relative import.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/r3-project-require", (req: Request, res: Response) => {
  checkUpload(req);
  req.pipe(fs.createWriteStream(p));
});
// A body helper that pipes to disk and returns the request, and a route with an early `return req`: items, failing.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
function saveBody(req: Request) {
  req.pipe(fs.createWriteStream(path.join(dir, req.query.name)));
  return req;
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/r3-early-return", (req: Request, res: Response) => {
  if (req.headers["x-skip"]) return req;
  req.pipe(fs.createWriteStream(p));
  res.end();
});
// A Next.js route writing the request's body stream.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
export async function PATCH(request: Request) {
  await writeFile(p, request.body);
  return request;
}
// A parsed body echoed back is no stream write.
// ok: upload-validation.typescript-nestjs.raw-body-upload
export async function OPTIONS(request: Request) {
  return Response.json(request.body);
}

// A body read whole, then stored, is a raw-body upload. Each fails with no checks in view.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/c-for-await", async (req: Request, res: Response) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  fs.writeFileSync(p, Buffer.concat(chunks));
});
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
export async function PUT(request: Request) {
  const buf = Buffer.from(await request.arrayBuffer());
  await writeFile(p, buf);
  return Response.json({});
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
async function storeText(request: Request) {
  const body = await request.text();
  await kv.put(randomUUID(), body);
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
async function storeBlob(request: Request) {
  const blob = await request.blob();
  await bucket.upload(randomUUID(), blob);
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
export async function DELETE(request: Request) {
  const reader = request.body.getReader();
  await sink.write(await reader.read());
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/c-read", (req: Request, res: Response) => {
  const chunk = req.read();
  fs.appendFileSync(p, chunk);
});
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/c-readable", (req: Request, res: Response) => {
  stream.Readable.from(req).pipe(fs.createWriteStream(p));
});
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
async function fastifyUpload(request: Request, reply) {
  request.raw.pipe(fs.createWriteStream(p));
}
// A body read whole and not stored: held, never failed. A for-await read is not shown safe.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/c-json", async (req: Request, res: Response) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  res.json(JSON.parse(Buffer.concat(chunks).toString()));
});
// A bare verify* function may store what it is given: held, not skipped.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
export async function HEAD(request: Request) {
  const raw = await request.text();
  if (!verifySignature(raw, request.headers.get("stripe-signature"))) return new Response(null, { status: 400 });
  return new Response(null);
}

// A raw body parser with a limit in the route's middleware is the size check; without a limit it isn't.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/b-raw-limit", express.raw({ type: "*/*", limit: "50mb" }), (req: Request, res: Response) => {
  fs.writeFileSync(path.join(dir, randomUUID()), req.body);
  res.end();
});
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/b-raw-nolimit", bodyParser.raw({ type: "*/*" }), (req: Request, res: Response) => {
  fs.writeFileSync(path.join(dir, randomUUID()), req.body);
  res.end();
});

// A "relative" source inside node_modules is a package, not project code: nothing is held.
import nmHelper from "../../node_modules/pkg";
const nmRequired = require("./node_modules/other");
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/a-nm-import", async (req: Request, res: Response) => {
  nmHelper(req);
  req.pipe(ws);
});
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/a-nm-require", async (req: Request, res: Response) => {
  nmRequired(req);
  req.pipe(ws);
});

// Any whole-body read makes an item, held whatever follows; it fails only where the
// body reaches a known store. Held: a database row, a query, a fetch, a key-value set, a project helper.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
async function rowSave(request: Request) {
  const buf = Buffer.from(await request.arrayBuffer());
  await prisma.file.create({ data: { blob: buf } });
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
async function querySave(request: Request) {
  const buf = Buffer.from(await request.arrayBuffer());
  await db.query("insert into files(data) values ($1)", [buf]);
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
async function forwardSave(request: Request) {
  const buf = await request.arrayBuffer();
  await fetch(externalStorage, { method: "PUT", body: buf });
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
async function kvSave(request: Request) {
  const raw = await request.text();
  if (!verifySignature(raw)) return new Response(null, { status: 401 });
  await kv.set(key, raw);
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
async function helperSave(request: Request) {
  return new Response(await processAndStore(Buffer.from(await request.arrayBuffer())));
}
// Known stores fail: a cloud bucket's save, an image written to a file, Bun.write, a blob client's uploadData.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
async function gcsSave(request: Request) {
  const buf = Buffer.from(await request.arrayBuffer());
  await gcs.bucket(b).file(n).save(buf);
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
async function imageSave(request: Request) {
  await sharp(Buffer.from(await request.arrayBuffer())).toFile(p);
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
async function bunSave(request: Request) {
  await Bun.write(p, await request.arrayBuffer());
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
async function blobSave(request: Request) {
  await blobClient.uploadData(await request.arrayBuffer());
}
// Webhooks: a raw body only verified and parsed as JSON makes no item (a declared read used only by the HMAC, the
// timing-safe compare and JSON.parse; a read passed straight to constructEvent or JSON.parse).
// ok: upload-validation.typescript-nestjs.raw-body-upload
async function signedHook(request: Request) {
  const raw = await request.text();
  const sig = request.headers.get("x-signature");
  const expected = crypto.createHmac("sha256", SECRET).update(raw).digest("hex");
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return new Response(null, { status: 401 });
  const event = JSON.parse(raw);
  await handleEvent(event);
}
// ok: upload-validation.typescript-nestjs.raw-body-upload
async function stripeHook(request: Request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get("stripe-signature"), SECRET);
  await handleEvent(event);
}
// ok: upload-validation.typescript-nestjs.raw-body-upload
async function jsonOnly(request: Request) {
  return Response.json(JSON.parse(await request.text()));
}
// A report whose length is checked before it is parsed (a CSP report endpoint): its length is no use of the body.
// ok: upload-validation.typescript-nestjs.raw-body-upload
async function cspReport(request: Request) {
  const text = await request.text();
  if (text.length > MAX_BODY_BYTES) return new Response(null, { status: 204 });
  Sentry.captureMessage("CSP", { extra: JSON.parse(text) });
}
// A verified body that is also kept is no longer only verified: held.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
async function verifiedKept(request: Request) {
  const raw = await request.text();
  if (!verifySignature(raw)) return new Response(null, { status: 401 });
  await queue.push({ raw });
}

// Only library verifiers make a read safe; request aliases and destructured bodies
// are reads too.
import { verifyAndSave, verifyThenStore } from "./store";
import { signer } from "./signer";
import jwt from "jsonwebtoken";
// A project function named verify* may store what it is given: held.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
async function projectVerify(request: Request) {
  const buf = Buffer.from(await request.arrayBuffer());
  await verifyAndSave(buf);
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
async function projectVerifyThen(request: Request) {
  const buf = await request.arrayBuffer();
  await verifyThenStore(buf);
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
async function projectMemberVerify(request: Request) {
  const raw = await request.text();
  signer.verify(raw);
}
// A package's verify (jwt.verify) only checks the body: no item.
// ok: upload-validation.typescript-nestjs.raw-body-upload
async function packageVerify(request: Request) {
  const raw = await request.text();
  jwt.verify(raw, KEY);
  return Response.json({});
}
// An alias of the request, a destructured parameter, a destructured const and a Response around the body: reads.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
async function aliasRead(request: Request) {
  const r = request;
  await put(await r.arrayBuffer());
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
async function bodyParam({ body }: Request) {
  const reader = body.getReader();
  await putObject(await reader.read());
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
async function bodyConst(request: Request) {
  const { body } = request;
  for await (const c of body) await put(c);
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
async function responseAround(request: Request) {
  const { body } = request;
  await put(await new Response(body).arrayBuffer());
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
async function responseAroundHeld(request: Request) {
  await kv.set(key, await new Response(request.body).text());
}
// The held fallback: in a request function, a whole read on any receiver holds.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
async function otherAlias(request: Request) {
  const r = cache;
  return Response.json(await r.text());
}
// Not reads: a download (a value bound from fetch), and a destructured body only echoed.
// ok: upload-validation.typescript-nestjs.raw-body-upload
async function fetchDownload(request: Request) {
  const res = await fetch(upstream);
  return Response.json(await res.text());
}
// ok: upload-validation.typescript-nestjs.raw-body-upload
async function bodyEcho({ body }: Request) {
  return Response.json({ body });
}
// A value whose own name says base64 is a data-URL write (held); a file name is not.
class DocRows {
  // ruleid: upload-validation.typescript-nestjs.data-url-write
  // ruleid: upload-validation.typescript-nestjs.type-candidate-data-url
  async createDoc(body: CreateDocDto) {
    await prisma.doc.create({ data: { file: body.fileBase64 } });
  }
  // ok: upload-validation.typescript-nestjs.data-url-write
  // ok: upload-validation.typescript-nestjs.type-candidate-data-url
  async createName(body: CreateDocDto) {
    await prisma.doc.create({ data: { file: body.fileName } });
  }
}

// The held fallback. In a function taking a request, a whole read on any receiver
// holds: an alias chain, a clone, a renamed destructure, ctx.request.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
async function aliasChain(request: Request) {
  const a = request;
  const b = a;
  await put(await b.arrayBuffer());
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
async function cloned(request: Request) {
  const copy = request.clone();
  await put(await copy.arrayBuffer());
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
async function renamedBody(request: Request) {
  const { body: stream } = request;
  for await (const c of stream) await put(c);
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
async function koaStyle(ctx) {
  await put(await ctx.request.arrayBuffer());
}
// A package verifier only (some-sdk's verify): no item; the same verifier with the body then put in a store: fails.
import vault from "some-vault-sdk";
// ok: upload-validation.typescript-nestjs.raw-body-upload
async function packageVerified(request: Request) {
  const buf = await request.arrayBuffer();
  await vault.verify(buf);
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
async function packageVerifiedKept(request: Request) {
  const buf = await request.arrayBuffer();
  if (!vault.verify(buf)) return;
  await put(buf);
}
// No request in the function: no fallback.
// ok: upload-validation.typescript-nestjs.raw-body-upload
async function readFixture(path) {
  const res = new Response(await readFile(path));
  return res.text();
}

// Downloads are not reads of the request: a stored file streamed to the client, a storage download read whole.
// ok: upload-validation.typescript-nestjs.raw-body-upload
app.get("/files/:id", async (req: Request, res: Response) => {
  const stream = await storage.readBinary(req.params.id);
  await pipeline(stream, res);
});
// ok: upload-validation.typescript-nestjs.raw-body-upload
async function reportDownload(request: Request) {
  const { data: fileData } = await supabase.storage.from("reports").download(path);
  return Response.json({ size: (await fileData.arrayBuffer()).byteLength });
}

// The request stream forwarded as a value. Held; failing into a known store.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/fwd-req", async (req: Request, res: Response) => {
  const response = await fetch(url, { method: "POST", body: req, duplex: "half" });
  res.json({ ok: response.ok });
});
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
async function fwdBody(request: Request) {
  await fetch(storageUrl, { method: "PUT", body: request.body, duplex: "half" });
  return Response.json({});
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
async function s3Body(request: Request) {
  await s3.send(new PutObjectCommand({ Bucket: b, Key: k, Body: request.body }));
}
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/fwd-upload", async (req: Request, res: Response) => {
  await new Upload({ client: s3, params: { Bucket: b, Key: k, Body: req } }).done();
  res.end();
});
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/fwd-await", async (req: Request, res: Response) => {
  const buf = await req.body;
  await queue.push(buf);
});
// A parsed body forwarded as JSON is not the request stream.
// ok: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/fwd-json", async (req: Request, res: Response) => {
  await fetch(url, { method: "POST", body: JSON.stringify(req.body) });
  await db.save({ name: req.body.name });
  res.end();
});

// One violation now covers both checks, so the size exemptions are shown with a type check in view:
// a raw parser's limit is the size check; without the limit the handler fails.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/z1b", express.raw({ type: "*/*", limit: "50mb" }), async (req: Request, res: Response) => {
  const type = await fileTypeFromBuffer(req.body);
  if (!type || !ALLOWED.includes(type.mime)) return res.sendStatus(415);
  fs.writeFileSync(path.join(dir, randomUUID()), req.body);
});
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/z1c", express.raw({ type: "*/*" }), async (req: Request, res: Response) => {
  const type = await fileTypeFromBuffer(req.body);
  if (!type || !ALLOWED.includes(type.mime)) return res.sendStatus(415);
  fs.writeFileSync(path.join(dir, randomUUID()), req.body);
});

// A bare req.body (a Buffer after express.raw or bodyParser.raw) forwarded as a value.
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/r1", express.raw({ type: "*/*", limit: "20mb" }), async (req: Request, res: Response) => {
  await fetch(storageUrl, { method: "PUT", body: req.body });
  res.end();
});
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/r2", express.raw({ type: "*/*", limit: "20mb" }), async (req: Request, res: Response) => {
  await s3.putObject({ Bucket: b, Key: k, Body: req.body });
  res.end();
});
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/r6", bodyParser.raw({ limit: "5mb" }), async (req: Request, res: Response) => {
  const buf: Buffer = req.body;
  await storage.upload(key, buf);
});
// ruleid: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/r7", async (req: Request, res: Response) => {
  const payload = req.body;
  await fetch(storageUrl, { method: "PUT", body: payload });
});
// Not forwarded as the body: stringified, a member of it, a name that reaches no sink.
// ok: upload-validation.typescript-nestjs.raw-body-upload
// ok: upload-validation.typescript-nestjs.raw-body-unchecked
app.post("/r8", async (req: Request, res: Response) => {
  await fetch(url, { method: "POST", body: JSON.stringify(req.body) });
  await storage.upload(key, req.body.content);
  const input = req.body;
  res.json(validate(input));
});
// A NestJS @Req() parameter is the request whatever its name.
class RawFiles {
  // ruleid: upload-validation.typescript-nestjs.raw-body-upload
  // ruleid: upload-validation.typescript-nestjs.raw-body-unchecked
  async raw3(@Req() r: Request) {
    await this.s3.send(new PutObjectCommand({ Bucket: b, Key: k, Body: r.body }));
  }
  // ok: upload-validation.typescript-nestjs.raw-body-upload
  async notRaw(@Req() r: Request) {
    await this.s3.send(new PutObjectCommand({ Bucket: b, Key: k, Body: JSON.stringify(r.body) }));
  }
}
