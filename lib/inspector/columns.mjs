/* The column classifier and the observed tenancy (rule_bundle.md section 7, evaluator_api.md 1.6, enums
 * COLUMN_CLASSES, TECHNICAL_COLUMN_NAMES, TENANCY_MODELS). Both run on the machine over the catalog the inspector read;
 * only the class, and the tenancy model, are sent.
 *
 * classifyColumn(name, dataType) -> one of COLUMN_CLASSES
 *   The recognisers are name word lists matched on whole words: the name is split into words (underscores, dashes,
 *   spaces, digits and camelCase), and every run of up to four adjacent words is compared, joined, with each list
 *   (so first_name, firstName and firstname all match "first name"). The most sensitive class wins, in the order
 *   government_id, credential, financial, health, contact, direct_identifier. A name holding a letter outside ASCII
 *   after NFKC normalisation (mixed scripts, look-alike letters) is unknown. technical comes only from the published
 *   allowlist of whole names (TECHNICAL_COLUMN_NAMES, case folded), never as a fallback: any other name no recogniser
 *   matches is unknown, which goes to the person.
 *
 * observedTenancy({catalogStatus, policies, columns}) -> {model, tenant_column, source}
 *   Allowed as observed only while the catalog collector is ok or truncated, and never single. row_level only when
 *   every rls_policies row with tenant_comparison true compares one column (policyexpr reports which), that column is
 *   a tenant key (enums.TENANT_KEYS) and a column of the policy's own table, and all of them name the same column;
 *   otherwise unknown. Nothing is guessed from column names alone. Without a usable catalog nothing was
 *   observed: model unknown, with source answer (the schema requires the block and allows observed only with a usable
 *   catalog; unknown carries no claim either way). */
import { TENANT_KEYS } from "./policyexpr.mjs";

export const COLUMN_CLASSES = Object.freeze(["direct_identifier", "contact", "government_id", "health", "financial",
  "credential", "technical", "unknown"]);
export const TECHNICAL_COLUMN_NAMES = Object.freeze(["id", "uuid", "created_at", "updated_at", "deleted_at",
  "inserted_at", "modified_at", "archived_at", "version", "lock_version", "row_version", "etag", "sort_order", "position"]);

const WORDS = {
  government_id: ["ssn", "social security", "social security number", "social insurance number", "sin", "nhs number",
    "nhs no", "nhs", "medicare number", "medicare id", "medicare", "medicaid id", "medicaid number", "medicaid",
    "drivers license", "driver license", "drivers licence", "driver licence", "driving licence", "driving license",
    "dl number", "license number", "licence number", "passport", "passport number", "aadhaar", "aadhar", "cpf",
    "national id", "national identifier", "national insurance", "nino", "tax id", "taxpayer id", "tin", "itin",
    "voter id", "state id", "government id", "gov id", "govt id", "government identifier", "government number",
    "govt number", "gov number", "health card", "health card number", "personnummer", "bsn"],
  credential: ["password", "passwd", "pwd", "passcode", "pass hash", "password hash", "secret", "client secret",
    "token", "access token", "refresh token", "session token", "api key", "apikey", "access key", "private key",
    "secret key", "otp", "totp", "mfa secret", "recovery code", "recovery codes", "pin", "pin code", "credential",
    "credentials", "auth key", "signing key", "encryption key"],
  financial: ["card number", "credit card", "debit card", "cc number", "pan", "cvv", "cvc", "card cvc", "iban",
    "account number", "acct number", "bank account", "routing number", "sort code", "bank", "bic", "swift", "salary",
    "income", "payment", "payments", "billing", "invoice", "insurance", "insurer", "member id", "member number",
    "policy number", "group number", "subscriber id", "claim", "claims", "payer", "copay", "deductible", "balance due"],
  health: ["diagnosis", "diagnoses", "dx", "condition", "conditions", "medication", "medications", "medicine",
    "medicines", "drug", "drugs", "prescription", "prescriptions", "rx", "allergy", "allergies", "symptom", "symptoms",
    "treatment", "treatments", "procedure", "procedures", "icd", "icd10", "icd 10", "cpt", "snomed", "loinc", "lab",
    "labs", "lab result", "test result", "vital", "vitals", "blood", "blood type", "blood pressure", "bp",
    "heart rate", "pulse", "weight", "height", "bmi", "clinical", "medical", "health", "therapy", "mental",
    "psych", "psychiatric", "pregnancy", "pregnant", "hiv", "std", "sti", "vaccine", "vaccination", "immunization",
    "disability", "genetic", "genome", "dna", "disease", "illness", "injury", "encounter", "appointment",
    "admission", "discharge", "chart", "dosage", "dose", "surgery", "care plan", "clinical notes",
    "progress note", "progress notes", "triage", "referral", "pathology", "radiology", "imaging", "substance",
    "alcohol", "smoking", "sexual", "contraception", "chief complaint", "complaint", "soap note", "a1c", "hba1c",
    "hemoglobin a1c", "phq", "gad", "glucose", "blood glucose", "buprenorphine", "methadone", "naloxone", "toxicology",
    "tox screen",
    // Notes a clinician writes or a visit leaves, as the evaluator's recognizer reads them.
    "physician note", "physician notes", "clinician note", "clinician notes", "provider note", "provider notes",
    "doctor note", "doctor notes", "nurse note", "nurse notes", "nursing note", "nursing notes", "visit note",
    "visit notes", "consult note", "consult notes", "consultation note", "consultation notes", "therapist note",
    "therapist notes", "session note", "session notes"],
  contact: ["email", "e mail", "email address", "phone", "phone number", "telephone", "tel", "mobile", "cell",
    "fax", "address", "street", "street address", "address line", "city", "zip", "zipcode", "zip code", "postal",
    "postal code", "postcode", "county", "contact", "emergency contact", "next of kin", "guardian"],
  direct_identifier: ["first name", "last name", "full name", "middle name", "given name", "family name",
    "maiden name", "surname", "forename", "patient name", "legal name", "preferred name", "nickname", "dob",
    "date of birth", "birth date", "birthdate", "birthday", "born", "age", "mrn", "medical record",
    "medical record number", "record number", "chart number", "patient id", "patient number", "patient",
    "ip address", "ip addr", "ip", "device id", "serial number", "mac address", "biometric", "biometrics",
    "fingerprint", "face", "photo", "photograph", "picture", "selfie", "signature", "license plate", "vehicle", "vin",
    "gender", "sex", "race", "ethnicity", "religion", "date of death", "deceased", "death date", "fname", "lname",
    "birth year", "year of birth"],
};
const ORDER = ["government_id", "credential", "financial", "health", "contact", "direct_identifier"];
const LOOKUP = new Map();
for (const cls of [...ORDER].reverse()) for (const phrase of WORDS[cls]) LOOKUP.set(phrase.replaceAll(" ", ""), cls);
const RANK = new Map(ORDER.map((c, i) => [c, i]));
const TECHNICAL = new Set(TECHNICAL_COLUMN_NAMES);
const MAX_SPAN = 4;

// Digits split words (icd10, address2, ipv4Address). A letter-digit-letter run is also read whole, but only when it is
// a listed abbreviation (a1c, hba1c), so a1c never reads only as "a c" and icd10Code still reads "icd code"
//.
function readings(name) {
  const tokens = name
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/);
  const split = tokens.flatMap((w) => w.split(/\d+/)).filter(Boolean);
  const whole = tokens.flatMap((w) => (/^[a-z]+\d+[a-z]+$/.test(w) && LOOKUP.has(w) ? [w] : w.split(/\d+/))).filter(Boolean);
  return whole.length === split.length ? [split] : [split, whole];
}

export function classifyColumn(name, dataType = "") {
  if (typeof name !== "string" || name === "") return "unknown";
  const norm = name.normalize("NFKC");
  if (/[^\x00-\x7f]/.test(norm)) return "unknown"; // mixed or non-Latin scripts, look-alike letters: the person decides
  let best = null;
  for (const w of readings(norm)) {
    for (let i = 0; i < w.length; i++) {
      let joined = "";
      for (let j = i; j < Math.min(w.length, i + MAX_SPAN); j++) {
        joined += w[j];
        const cls = LOOKUP.get(joined);
        if (cls && (best === null || RANK.get(cls) < RANK.get(best))) best = cls;
      }
    }
  }
  if (best) return best;
  const type = String(dataType).toLowerCase();
  if (type === "inet" || type === "cidr" || type === "macaddr" || type === "macaddr8") return "direct_identifier";
  if (TECHNICAL.has(norm.toLowerCase())) return "technical";
  return "unknown";
}

/* policies: [{schema, table, tenant_comparison, tenantColumns}] with raw names (tenantColumns: the row columns its
 * tenant equalities use, from policyexpr); columns: raw table_columns rows {schema, table, column, sentColumn}. */
export function observedTenancy({ catalogStatus, policies = [], columns = [] }) {
  if (catalogStatus !== "ok" && catalogStatus !== "truncated") return { model: "unknown", tenant_column: null, source: "answer" };
  const unknown = { model: "unknown", tenant_column: null, source: "observed" };
  const sentOf = new Map(columns.map((c) => [`${c.schema}\u0000${c.table}\u0000${c.column}`, c.sentColumn]));
  const candidates = new Set();
  for (const p of policies) {
    if (p.tenant_comparison !== true) continue;
    const used = p.tenantColumns ?? [];
    // The comparison must name exactly one column, and that column must be a tenant-key column of the policy's own
    // table (in table_columns); anything else isn't shown, so the model stays unknown.
    if (used.length !== 1 || !TENANT_KEYS.includes(used[0])) return unknown;
    const sent = sentOf.get(`${p.schema}\u0000${p.table}\u0000${used[0]}`);
    if (sent === undefined) return unknown;
    candidates.add(sent);
  }
  if (candidates.size !== 1) return unknown;
  return { model: "row_level", tenant_column: [...candidates][0], source: "observed" };
}
