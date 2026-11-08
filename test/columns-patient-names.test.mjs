// common patient columns the classifier missed. Digits split words, so a1c reads as "a c" and
// phq9 as "phq".
import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyColumn } from "../lib/inspector/columns.mjs";

const expected = {
  direct_identifier: ["fname", "lname", "patient_fname", "birth_year", "birthYear", "given_name", "family_name", "sex",
    "gender_identity"],
  health: ["chief_complaint", "soap_note", "discharge_summary", "encounter_note", "a1c", "hba1c", "hemoglobin_a1c",
    "phq9", "phq_9", "gad7", "bmi", "heart_rate", "blood_glucose", "glucose", "buprenorphine", "methadone",
    "toxicology", "tox_screen"],
};

test("common patient columns get their class", () => {
  for (const [cls, names] of Object.entries(expected)) {
    for (const name of names) assert.equal(classifyColumn(name, "text"), cls, name);
  }
});

test("near names stay out", () => {
  for (const name of ["filename", "gadget", "ac_unit", "complaints_url", "soap_version"]) {
    assert.notEqual(classifyColumn(name, "text"), "health", name);
  }
});

// The evaluator's recognizer table. Notes written by a clinician or about a visit are health here too; plain
// notes, release notes and admin notes stay unknown, as they stay deferred in core.
test("notes written by a clinician or about a visit are health", () => {
  for (const name of ["physician_notes", "providerNotes", "nurse_note", "nursing_notes", "doctor_notes", "clinician_note",
    "visit_notes", "therapist_notes", "session_notes", "consult_note", "consultation_notes", "progress_notes", "soap_note",
    "encounter_note", "clinician_diagnosis", "attending_diagnosis"]) {
    assert.equal(classifyColumn(name, "text"), "health", name);
  }
  assert.equal(classifyColumn("hospital_mrn", "text"), "direct_identifier");
  for (const name of ["notes", "release_notes", "admin_note"]) assert.equal(classifyColumn(name, "text"), "unknown", name);
});

// a camelCase name with a digit run kept the run as one word ("icd10code"), so it matched nothing.
// A run stays whole only as a listed abbreviation (a1c, hba1c); the split parts are looked up too.
test("camelCase names with a digit run keep their class", () => {
  const cases = {
    icd10Code: "health", covid19Diagnosis: "health", phq9Score: "health", gad7Score: "health", hbA1c: "health",
    hemoglobinA1c: "health", oauth2Token: "credential", ipv4Address: "contact", last4ssn: "government_id",
    w2Income: "financial", icd10_code: "health", oauth2_token: "credential", ipv4_address: "contact",
    last4_ssn: "government_id", w2_income: "financial", phq9_score: "health",
  };
  for (const [name, cls] of Object.entries(cases)) assert.equal(classifyColumn(name, "text"), cls, name);
});
