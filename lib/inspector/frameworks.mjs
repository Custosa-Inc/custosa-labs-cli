/* Frameworks from the project's manifests (fact schema files.frameworks, enums.FRAMEWORKS): package.json
 * dependencies, Python requirement files and pyproject.toml, Gemfile, composer.json, go.mod, Maven and Gradle files,
 * .csproj files, Terraform files, GitHub Actions workflows, supabase/config.toml and firebase.json.
 *
 * detectFrameworks(root, walkResult) -> {frameworks: string[] | null, fromPaths: string[], problems: [{path, reason}]}
 *   frameworks is null when a manifest the walk found couldn't be read or parsed (too large, unreadable, invalid
 *   JSON): the frameworks are then unknown, and the rule collector runs only generic rules and lists every file whose
 *   language has framework rules as not analysed (runRules' frameworks_unknown). fromPaths: the frameworks known from
 *   paths alone (terraform, github_actions, supabase, firebase), which stand either way. problems: each manifest that
 *   couldn't be read (unreadable, too_large) or parsed (parse_error), for files.not_analyzed. Manifests are read
 *   through walkread (never a .env file), at most 1 MB each.
 *
 * fingerprints (files.fingerprints): the kinds of service the project declares, from the same manifests plus
 *   pubspec.yaml, Podfile, Gradle version catalogs (gradle/libs.versions.toml) and SwiftPM's Package.swift and
 *   Package.resolved (read for this only), and marker files (AndroidManifest.xml, Info.plist, a .pbxproj,
 *   google-services.json, GoogleService-Info.plist, the Firebase rules and config files, Package.swift). mobile_hybrid
 *  : Capacitor, Cordova, Ionic and NativeScript packages, .NET MAUI and the Kotlin Multiplatform plugin.
 *   vector_store_sdk: vector-store clients (Pinecone, Weaviate, Qdrant, Chroma, Milvus, pgvector and the
 *   like) in every ecosystem; evidence for rag-retrieval-scoped's contradiction check, it never closes an item. The
 *   import scan (imports.mjs) adds what JS, TS and Python source imports. Presence only: an empty list means no declared
 *   dependency of these kinds, never that the code makes no such call. null when any manifest couldn't be read or parsed, or a
 *   skipped directory could hold one; then it is sent absent. Matching is broad on purpose: a wrong presence only keeps
 *   an item open, a wrong absence could close one. */
import { readWalked } from "./walkread.mjs";
import { parseToml } from "./tomlparse.mjs";
import { ecosystemOf } from "./manifests.mjs";
import { SUPABASE_CONFIG_PATTERN } from "./edgefunctions.mjs";

const MAX_BYTES = 1_000_000;
const MAX_MANIFESTS = 2000;
export const FRAMEWORKS = Object.freeze(["express", "nextjs", "nestjs", "fastify", "hono", "koa", "remix", "sveltekit",
  "nuxt", "django", "flask", "fastapi", "rails", "laravel", "spring", "gin", "echo", "aspnetcore", "prisma", "drizzle",
  "typeorm", "sequelize", "sqlalchemy", "alembic", "knex", "supabase", "firebase", "expo", "react_native", "terraform",
  "github_actions"]);

const NPM = [
  [/^express$/, "express"], [/^next$/, "nextjs"], [/^@nestjs\/core$/, "nestjs"], [/^fastify$/, "fastify"],
  [/^hono$/, "hono"], [/^koa$/, "koa"], [/^@remix-run\//, "remix"], [/^@sveltejs\/kit$/, "sveltekit"],
  [/^nuxt3?$/, "nuxt"], [/^(prisma|@prisma\/client)$/, "prisma"], [/^drizzle-orm$/, "drizzle"], [/^typeorm$/, "typeorm"],
  [/^sequelize$/, "sequelize"], [/^knex$/, "knex"], [/^@supabase\//, "supabase"], [/^(firebase|firebase-admin|firebase-functions)$/, "firebase"],
  [/^expo$/, "expo"], [/^react-native$/, "react_native"],
];
export const FINGERPRINTS = Object.freeze(["ai_sdk", "android", "error_tracking_sdk", "firebase_sdk", "flutter", "ios",
  "mobile_hybrid", "object_storage_sdk", "realtime_sdk", "vector_store_sdk"]);

// Dependency names per ecosystem, as [pattern, fingerprint]. supabase-js and Rails carry realtime but are not listed:
// the evaluator reads them from frameworks.
const SDK = {
  npm: [
    [/^(openai|@anthropic-ai\/.+|ai|@ai-sdk\/.+|langchain|@langchain\/.+|llamaindex|cohere-ai|@google\/(generative-ai|genai)|@google-cloud\/(vertexai|aiplatform)|@mistralai\/.+|groq-sdk|replicate|@huggingface\/inference|@aws-sdk\/client-bedrock(-runtime|-agent-runtime)?|@azure\/openai|@openai\/.+|together-ai|ollama)$/, "ai_sdk"],
    [/^(@aws-sdk\/(client-s3|lib-storage|s3-request-presigner)|aws-sdk|@google-cloud\/storage|@azure\/storage-blob|@vercel\/blob|minio|uploadthing|@uploadthing\/.+|cloudinary|@cloudflare\/r2)$/, "object_storage_sdk"],
    [/^(socket\.io|socket\.io-client|pusher|pusher-js|ably|@ably\/.+|@pusher\/.+|ws|@liveblocks\/.+|partykit|partysocket|@supabase\/realtime-js|centrifuge|@microsoft\/signalr)$/, "realtime_sdk"],
    [/^(@sentry\/.+|@bugsnag\/.+|bugsnag|rollbar|@datadog\/browser-(rum|logs)|dd-trace|logrocket|@highlight-run\/.+|highlight\.run|@honeybadger-io\/.+|trackjs|@react-native-firebase\/crashlytics|@appsignal\/.+|newrelic|@newrelic\/.+|raygun4js)$/, "error_tracking_sdk"],
    [/^(firebase|firebase-admin|firebase-functions|@react-native-firebase\/.+|@angular\/fire|reactfire|@firebase\/.+|@google-cloud\/firestore)$/, "firebase_sdk"],
    [/^(@capacitor\/.+|cordova|cordova-.+|@ionic\/.+|@nativescript\/.+)$/, "mobile_hybrid"],
    [/^(@pinecone-database\/pinecone|weaviate-client|weaviate-ts-client|@qdrant\/(js-client-rest|js-client-grpc|qdrant-js)|chromadb|@zilliz\/milvus2-sdk-node|pgvector|@upstash\/vector|@turbopuffer\/turbopuffer|@lancedb\/lancedb|vectordb|@datastax\/astra-db-ts|@langchain\/(pinecone|qdrant|weaviate|mongodb|redis)|@llamaindex\/(pinecone|qdrant|weaviate|chroma|milvus|postgres|astra|upstash))$/, "vector_store_sdk"],
  ],
  python: [
    [/^(openai|anthropic|langchain|langchain-.+|langgraph|llama-index|llama-index-.+|cohere|google-generativeai|google-genai|google-cloud-aiplatform|vertexai|mistralai|groq|litellm|replicate|huggingface-hub|transformers|together|ollama|instructor|dspy|dspy-ai)$/, "ai_sdk"],
    [/^(boto3|aiobotocore|s3fs|google-cloud-storage|azure-storage-blob|minio|django-storages|cloudinary)$/, "object_storage_sdk"],
    [/^(python-socketio|flask-socketio|channels|pusher|ably|websockets|django-channels)$/, "realtime_sdk"],
    [/^(sentry-sdk|raven|bugsnag|rollbar|ddtrace|honeybadger|newrelic)$/, "error_tracking_sdk"],
    [/^(firebase-admin|pyrebase|pyrebase4|google-cloud-firestore)$/, "firebase_sdk"],
    [/^(pinecone|pinecone-client|weaviate-client|qdrant-client|chromadb|chromadb-client|pymilvus|pgvector|vecs|lancedb|faiss|faiss-cpu|faiss-gpu|upstash-vector|turbopuffer|astrapy|redisvl|langchain-(pinecone|qdrant|weaviate|chroma|milvus|postgres)|llama-index-vector-stores-.+)$/, "vector_store_sdk"],
  ],
  ruby: [
    [/^(ruby-openai|openai|anthropic|langchainrb|ruby_llm|cohere-ruby|gemini-ai)$/, "ai_sdk"],
    [/^(aws-sdk-s3|aws-sdk|google-cloud-storage|azure-storage-blob|fog-aws|shrine|carrierwave|activestorage)$/, "object_storage_sdk"],
    [/^(pusher|ably|anycable|anycable-rails|faye-websocket)$/, "realtime_sdk"],
    [/^(sentry-ruby|sentry-rails|sentry-raven|bugsnag|rollbar|ddtrace|datadog|honeybadger|newrelic_rpm|appsignal)$/, "error_tracking_sdk"],
    [/^(firebase|firebase-admin-sdk|google-cloud-firestore)$/, "firebase_sdk"],
    [/^(pinecone|qdrant-ruby|weaviate-ruby|chroma-db|milvus|pgvector|neighbor)$/, "vector_store_sdk"],
  ],
  php: [
    [/^(openai-php\/.+|anthropic-ai\/.+|mozex\/anthropic-php|theodo-group\/llphant|prism-php\/prism|google-gemini-php\/.+)$/, "ai_sdk"],
    [/^(aws\/aws-sdk-php|league\/flysystem-aws-s3-v3|google\/cloud-storage|microsoft\/azure-storage-blob|league\/flysystem-.+)$/, "object_storage_sdk"],
    [/^(pusher\/pusher-php-server|ably\/ably-php|beyondcode\/laravel-websockets|laravel\/reverb)$/, "realtime_sdk"],
    [/^(sentry\/.+|bugsnag\/.+|rollbar\/.+|datadog\/.+|honeybadger-io\/.+)$/, "error_tracking_sdk"],
    [/^(kreait\/.+|google\/cloud-firestore)$/, "firebase_sdk"],
    [/^(probots-io\/pinecone-php|hkulekci\/qdrant|codewithkyrian\/chromadb-php|pgvector\/pgvector)$/, "vector_store_sdk"],
  ],
  pub: [
    [/^(google_generative_ai|firebase_vertexai|firebase_ai|dart_openai|openai_dart|anthropic_sdk_dart|langchain|langchain_.+)$/, "ai_sdk"],
    [/^(aws_s3_api|minio|flutter_uploader|amplify_storage_s3)$/, "object_storage_sdk"],
    [/^(socket_io_client|pusher_channels_flutter|ably_flutter|web_socket_channel)$/, "realtime_sdk"],
    [/^(sentry|sentry_flutter|sentry_dart|firebase_crashlytics|bugsnag_flutter|datadog_flutter_plugin|rollbar_flutter)$/, "error_tracking_sdk"],
    [/^(firebase_.+|cloud_firestore|cloud_functions)$/, "firebase_sdk"],
  ],
};
// Text patterns for manifests read as text: Go modules, JVM build files, .csproj and Podfile.
const TEXT = {
  go: [
    [/github\.com\/(sashabaranov\/go-openai|openai\/openai-go|anthropics\/anthropic-sdk-go|tmc\/langchaingo|google\/generative-ai-go)|google\.golang\.org\/genai|cloud\.google\.com\/go\/(vertexai|aiplatform)|aws-sdk-go-v2\/service\/bedrock/, "ai_sdk"],
    [/aws-sdk-go(-v2)?\/service\/s3\b|github\.com\/aws\/aws-sdk-go\s|cloud\.google\.com\/go\/storage|azure-sdk-for-go\/sdk\/storage\/azblob|github\.com\/minio\/minio-go/, "object_storage_sdk"],
    [/github\.com\/(gorilla\/websocket|pusher\/pusher-http-go|ably\/ably-go|googollee\/go-socket\.io|centrifugal\/centrifuge)|nhooyr\.io\/websocket|github\.com\/coder\/websocket/, "realtime_sdk"],
    [/github\.com\/(getsentry\/sentry-go|bugsnag\/bugsnag-go|rollbar\/rollbar-go|DataDog\/dd-trace-go|honeybadger-io\/honeybadger-go|newrelic\/go-agent)|gopkg\.in\/DataDog\/dd-trace-go/, "error_tracking_sdk"],
    [/firebase\.google\.com\/go|cloud\.google\.com\/go\/firestore/, "firebase_sdk"],
    [/github\.com\/(pinecone-io\/go-pinecone|qdrant\/go-client|weaviate\/weaviate-go-client|milvus-io\/milvus-sdk-go|pgvector\/pgvector-go|amikos-tech\/chroma-go)/, "vector_store_sdk"],
  ],
  jvm: [
    [/com\.openai|com\.anthropic|dev\.langchain4j|com\.theokanning\.openai|com\.google\.cloud:google-cloud-(vertexai|aiplatform)|com\.google\.genai|org\.springframework\.ai|software\.amazon\.awssdk:bedrock|com\.google\.ai\.client\.generativeai|com\.google\.firebase:firebase-(vertexai|ai)/, "ai_sdk"],
    [/software\.amazon\.awssdk[:"'\s]*\S*\bs3\b|<artifactId>s3<\/artifactId>|aws-java-sdk-s3|com\.google\.cloud:google-cloud-storage|com\.azure:azure-storage-blob|io\.minio/, "object_storage_sdk"],
    [/socket\.io|com\.pusher|io\.ably|spring-boot-starter-websocket|org\.java-websocket|okhttp3?\.ws|com\.microsoft\.signalr/, "realtime_sdk"],
    [/io\.sentry|com\.bugsnag|com\.rollbar|com\.datadoghq|firebase-crashlytics|io\.honeybadger|com\.newrelic/, "error_tracking_sdk"],
    [/com\.google\.firebase|com\.google\.gms[.:]google-services|com\.google\.gms\.google-services|google-cloud-firestore|dev\.gitlive/, "firebase_sdk"],
    [/com\.android\.(application|library)/, "android"],
    [/org\.jetbrains\.kotlin\.multiplatform|kotlin\(\s*["']multiplatform["']\s*\)/, "mobile_hybrid"],
    [/io\.pinecone|io\.qdrant|io\.weaviate|io\.milvus|com\.pgvector|spring-ai-[\w-]*(vector|store)\b|langchain4j-(pinecone|qdrant|weaviate|milvus|chroma|pgvector)\b/, "vector_store_sdk"],
  ],
  dotnet: [
    [/Include="(OpenAI|Azure\.AI\.OpenAI|Anthropic\.SDK|Anthropic|Microsoft\.SemanticKernel[^"]*|Microsoft\.Extensions\.AI[^"]*|LangChain[^"]*|Google\.Cloud\.AIPlatform[^"]*|AWSSDK\.BedrockRuntime|Mscc\.GenerativeAI[^"]*)"/i, "ai_sdk"],
    [/Include="(AWSSDK\.S3|Google\.Cloud\.Storage\.V1|Azure\.Storage\.Blobs|Minio)"/i, "object_storage_sdk"],
    [/Include="(Microsoft\.AspNetCore\.SignalR[^"]*|PusherServer|PusherClient|IO\.Ably|SocketIOClient)"/i, "realtime_sdk"],
    [/Include="(Sentry[^"]*|Bugsnag[^"]*|Rollbar[^"]*|Datadog\.Trace[^"]*|NewRelic\.Agent[^"]*|Raygun[^"]*)"/i, "error_tracking_sdk"],
    [/Include="(FirebaseAdmin|Google\.Cloud\.Firestore[^"]*)"/i, "firebase_sdk"],
    [/Include="Microsoft\.Maui[^"]*"|<UseMaui>\s*true\s*<\/UseMaui>/i, "mobile_hybrid"],
    [/Include="(Pinecone\.Client|Qdrant\.Client|Pgvector[^"]*|ChromaDB\.Client)"/i, "vector_store_sdk"],
  ],
  pod: [
    [/pod\s+["'](OpenAI|SwiftOpenAI|GoogleGenerativeAI|FirebaseVertexAI|FirebaseAI)/, "ai_sdk"],
    [/pod\s+["'](AWSS3|Amplify\/?Storage|AWSPluginsCore)/, "object_storage_sdk"],
    [/pod\s+["'](Socket\.IO-Client-Swift|PusherSwift|Ably|Starscream)/, "realtime_sdk"],
    [/pod\s+["'](Sentry|Bugsnag|Rollbar|DatadogSDK|DatadogCore|Firebase\/Crashlytics|FirebaseCrashlytics|Instabug)/, "error_tracking_sdk"],
    [/pod\s+["'](Firebase|GoogleService)/, "firebase_sdk"],
  ],
};
// Marker files by name: their presence alone is the fingerprint.
const FIREBASE_MARKERS = new Set(["firestore.rules", "storage.rules", ".firebaserc", "database.rules.json", "firestore.indexes.json"]);
const MARKERS = [
  [(p) => base(p) === "AndroidManifest.xml", ["android"]],
  [(p) => base(p) === "Info.plist" || /\.xcodeproj\/project\.pbxproj$/.test(p) || base(p) === "Podfile", ["ios"]],
  [(p) => base(p) === "google-services.json", ["firebase_sdk"]],
  [(p) => base(p) === "GoogleService-Info.plist", ["firebase_sdk", "ios"]],
  [(p) => FIREBASE_MARKERS.has(base(p)), ["firebase_sdk"]],
  [(p) => base(p) === "Package.swift" || base(p) === "Package.resolved", ["ios"]],
];
// Read for the fingerprint only, so a problem with one never changes the frameworks.
function fpKindOf(path) {
  const b = base(path);
  if (b === "pubspec.yaml") return "pub";
  if (b === "Podfile") return "pod";
  if (/(?:^|\/)gradle\/libs\.versions\.toml$/.test(path)) return "gradle_catalog";
  if (b === "Package.swift" || b === "Package.resolved") return "swiftpm";
  return null;
}

const PY = [[/^django$/, "django"], [/^flask$/, "flask"], [/^fastapi$/, "fastapi"], [/^sqlalchemy$/, "sqlalchemy"],
  [/^alembic$/, "alembic"], [/^supabase$/, "supabase"], [/^firebase-admin$/, "firebase"]];
const base = (p) => p.slice(p.lastIndexOf("/") + 1);

// Python lockfiles name only what their manifest does: not read for frameworks.
const PY_LOCK = /(?:^|\/)(?:Pipfile\.lock|poetry\.lock|uv\.lock|pdm\.lock|pylock(?:\.[^/]*)?\.toml)$/;

function kindOf(path) {
  const b = base(path), lower = b.toLowerCase();
  if (b === "package.json") return "npm";
  // every file manifests.mjs counts as pip (requirements/, requirements.d/, .in, dev- and test-), less locks.
  if (/^requirements.*\.txt$/i.test(b) || (ecosystemOf(path) === "pip" && !PY_LOCK.test(path))) return "python";
  if (b === "Gemfile") return "ruby";
  if (b === "composer.json") return "php";
  if (b === "go.mod") return "go";
  if (b === "pom.xml" || /^build\.gradle(\.kts)?$/.test(b)) return "jvm";
  if (lower.endsWith(".csproj")) return "dotnet";
  return null;
}

/** The frameworks the manifest tables give one package name (ecosystem npm or python; the import scan). */
export function frameworksOf(ecosystem, name) {
  return (ecosystem === "npm" ? NPM : PY).filter(([re]) => re.test(name)).map(([, fw]) => fw);
}

/** The fingerprints an SDK table gives one package name (ecosystem npm or python; the import scan, imports.mjs). */
export function sdkFingerprints(ecosystem, name) {
  return FINGERPRINTS.filter((fp) => SDK[ecosystem].some(([re, f]) => f === fp && re.test(name)));
}

const matchAll = (names, table, found) => {
  for (const d of names) for (const [re, fp] of table) if (re.test(d)) found.add(fp);
};
const matchText = (text, table, found) => {
  for (const [re, fp] of table) if (re.test(text)) found.add(fp);
};
// A directory skipped by the walk could hold a manifest, except a dependency or VCS folder git doesn't track.
export const hidesManifest = (e) => e.kind === "directory"
  && !(e.reason === "excluded_directory" && (e.tracked === "no" || /^(\.git|\.hg|\.svn)$/.test(e.path)));

/* The text of a Python manifest whose words can name a dependency. A comment never does (a # at a line's start or
 * after a space: a #egg= in a URL stays), nor pyproject.toml's descriptive fields. A framework read from a keyword or a
 * description ("a port of our Django app") would enable that framework's rules and count Python as covered. The same
 * goes for setup.cfg's [metadata] section and setup.py's descriptive arguments. A pyproject.toml the strict TOML reader
 * refuses is read as text, as before. */
const PY_METADATA = ["name", "version", "description", "readme", "keywords", "classifiers", "authors", "maintainers",
  "license", "license-files", "urls", "homepage", "repository", "documentation"];
// setup.py's descriptive arguments with a literal value: a string, a list or a dict.
const SETUP_METADATA = /\b(?:name|version|description|long_description|keywords|classifiers|url|download_url|author|author_email|maintainer|maintainer_email|license|project_urls|platforms)\s*=\s*(?:"""[\s\S]*?"""|'''[\s\S]*?'''|"[^"\n]*"|'[^'\n]*'|\[[^\]]*\]|\{[^}]*\})/g;
function pythonDeclared(path, text) {
  if (base(path) === "pyproject.toml") {
    try {
      const doc = parseToml(text);
      for (const table of [doc.project, doc.tool?.poetry]) {
        if (table && typeof table === "object") for (const k of PY_METADATA) delete table[k];
      }
      return JSON.stringify(doc);
    } catch { /* read as text below */ }
  }
  const words = text.replace(/(^|[ \t])#.*$/gm, "$1");
  if (base(path) === "setup.cfg") return words.replace(/^\[metadata\][^\n]*(?:\n(?!\[)[^\n]*)*/m, "");
  if (base(path) === "setup.py") return words.replace(SETUP_METADATA, "");
  return words;
}

/* What one manifest of `kind` declares: frameworks into `found`, fingerprints into `fps`. Throws on a manifest that
 * doesn't parse. */
function readManifest(kind, text, found, fps, path) {
  if (kind === "npm" || kind === "php") {
    const json = JSON.parse(text);
    const deps = new Set();
    for (const k of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "require", "require-dev"]) {
      const v = json && typeof json === "object" ? json[k] : undefined;
      if (v && typeof v === "object" && !Array.isArray(v)) for (const d of Object.keys(v)) deps.add(d);
    }
    if (kind === "npm") matchAll(deps, NPM, found);
    if (kind === "php" && deps.has("laravel/framework")) found.add("laravel");
    matchAll(deps, SDK[kind], fps);
  } else if (kind === "python") {
    const names = [...pythonDeclared(path, text).matchAll(/[A-Za-z0-9][A-Za-z0-9._-]*/g)].map((m) => m[0].toLowerCase().replaceAll("_", "-"));
    matchAll(names, PY, found);
    matchAll(names, SDK.python, fps);
  } else if (kind === "ruby") {
    if (/^\s*gem\s+["'](rails|railties|activerecord)["']/m.test(text)) found.add("rails");
    matchAll([...text.matchAll(/^\s*gem\s+["']([^"']+)["']/gm)].map((m) => m[1]), SDK.ruby, fps);
  } else if (kind === "go") {
    if (/github\.com\/gin-gonic\/gin\b/.test(text)) found.add("gin");
    if (/github\.com\/labstack\/echo\b/.test(text)) found.add("echo");
    matchText(text, TEXT.go, fps);
  } else if (kind === "jvm") {
    if (/org\.springframework/.test(text)) found.add("spring");
    matchText(text, TEXT.jvm, fps);
  } else if (kind === "dotnet") {
    if (/Microsoft\.NET\.Sdk\.Web|Microsoft\.AspNetCore/.test(text)) found.add("aspnetcore");
    matchText(text, TEXT.dotnet, fps);
  }
}

/* Dependency names from a pubspec.yaml: the keys under dependencies, dev_dependencies and dependency_overrides, at the
 * indent of the section's first entry. flutter is the app's SDK when a dependency `flutter:` has `sdk: flutter`. */
function pubspec(text) {
  const names = new Set();
  let flutter = false, section = false, indent = null, last = null;
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || /^\s*#/.test(line)) continue;
    if (/^\S/.test(line)) {
      section = /^(dependencies|dev_dependencies|dependency_overrides):\s*(#.*)?$/.test(line);
      indent = null; last = null;
      continue;
    }
    if (!section) continue;
    const lead = /^ */.exec(line)[0].length;
    indent ??= lead;
    if (lead === indent) {
      const dep = /^ *([A-Za-z0-9_]+)\s*:/.exec(line);
      last = dep ? dep[1] : null;
      if (dep) names.add(dep[1]);
    } else if (lead > indent && last === "flutter" && /^\s*sdk:\s*["']?flutter["']?\s*(#.*)?$/.test(line)) flutter = true;
  }
  return { names, flutter };
}

export async function detectFrameworks(root, walk) {
  const found = new Set(), fps = new Set();
  const problems = [];
  let unknown = false, fpUnknown = false;
  const files = walk.files ?? [];
  const skipped = walk.notAnalyzed ?? [];
  for (const p of [...files.map((f) => f.path), ...skipped.filter((e) => e.kind === "file").map((e) => e.path)]) {
    for (const [is, add] of MARKERS) if (is(p)) for (const fp of add) fps.add(fp);
  }
  if (skipped.some((e) => (e.kind === "file" && fpKindOf(e.path)) || hidesManifest(e))) fpUnknown = true;
  for (const f of files) {
    if (/\.tf$/i.test(f.path)) found.add("terraform");
    if (/(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/.test(f.path)) found.add("github_actions");
    if (SUPABASE_CONFIG_PATTERN.test(f.path)) found.add("supabase");
    if (base(f.path) === "firebase.json") found.add("firebase");
  }
  const fromPaths = FRAMEWORKS.filter((f) => found.has(f));
  const manifests = files.filter((f) => kindOf(f.path));
  // A manifest the walk listed but didn't keep (too large, unreadable, a symlink), or a skipped folder that could hold
  // one (as fingerprints and manifests already do), leaves the frameworks unknown.
  if (skipped.some((e) => (e.kind === "file" && kindOf(e.path)) || hidesManifest(e))) unknown = true;
  if (manifests.length > MAX_MANIFESTS) unknown = true;
  for (const f of manifests.slice(0, MAX_MANIFESTS)) {
    const read = await readWalked(root, f.disk ?? f.path, MAX_BYTES);
    if (!read.buf) { unknown = true; problems.push({ path: f.path, reason: read.refused }); continue; }
    try {
      readManifest(kindOf(f.path), read.buf.toString("utf8"), found, fps, f.path);
    } catch { unknown = true; problems.push({ path: f.path, reason: "parse_error" }); }
  }
  // pubspec.yaml, Podfile, Gradle version catalogs and SwiftPM files: read for the fingerprint only. A catalog's
  // library and plugin coordinates go through the JVM table.
  const fpManifests = files.filter((f) => fpKindOf(f.path));
  if (fpManifests.length > MAX_MANIFESTS) fpUnknown = true;
  for (const f of fpManifests.slice(0, MAX_MANIFESTS)) {
    const read = await readWalked(root, f.disk ?? f.path, MAX_BYTES);
    if (!read.buf) { fpUnknown = true; problems.push({ path: f.path, reason: read.refused }); continue; }
    const text = read.buf.toString("utf8");
    const kind = fpKindOf(f.path);
    if (kind === "pod") matchText(text, TEXT.pod, fps);
    else if (kind === "gradle_catalog") matchText(text, TEXT.jvm, fps);
    else if (kind === "swiftpm") { if (/firebase-ios-sdk/i.test(text)) fps.add("firebase_sdk"); }
    else {
      const { names, flutter } = pubspec(text);
      if (flutter) fps.add("flutter");
      matchAll(names, SDK.pub, fps);
    }
  }
  return { frameworks: unknown ? null : FRAMEWORKS.filter((f) => found.has(f)), fromPaths, problems,
    fingerprints: unknown || fpUnknown ? null : FINGERPRINTS.filter((f) => fps.has(f)) };
}
