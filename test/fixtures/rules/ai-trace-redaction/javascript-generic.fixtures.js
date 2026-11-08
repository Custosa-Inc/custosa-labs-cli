function show(record) {
  // ruleid: ai-trace-redaction.javascript-generic.console-phi
  console.log("record", record.patient);
  // ok: ai-trace-redaction.javascript-generic.console-phi
  console.log("loaded");
  // ruleid: ai-trace-redaction.javascript-generic.local-storage
  localStorage.setItem("p", JSON.stringify(record));
  // ok: ai-trace-redaction.javascript-generic.local-storage
  sessionStorage.setItem("theme", "dark");
}
