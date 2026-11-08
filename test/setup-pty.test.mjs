/* `npx custosa setup` in a real terminal (a pty from python3): Ctrl-C while `custosa login` waits stops the sign-in,
 * not the terminal, and setup carries on. The evaluator is the local stub; HOME and CUSTOSA_CONFIG_DIR are temporary. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { stub } from "./stub-evaluator.mjs";

const BIN = fileURLToPath(new URL("../bin/custosa.mjs", import.meta.url));
const HAS_PTY = process.platform !== "win32" && spawnSync("python3", ["-c", "import pty"]).status === 0;

/* Runs argv in a pty. steps: [[text to wait for, bytes to send], ...]. Prints the transcript, then "EXIT <code>". */
const DRIVER = String.raw`
import os, pty, sys, json, time, select
steps = json.loads(sys.argv[1]); argv = json.loads(sys.argv[2])
pid, fd = pty.fork()
if pid == 0:
    os.execvp(argv[0], argv)
buf = b""
def until(text, t=20):
    global buf
    end = time.time() + t
    while time.time() < end:
        if text.encode() in buf: return True
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try: d = os.read(fd, 4096)
            except OSError: return False
            if not d: return False
            buf += d
    return False
for wait, send in steps:
    if not until(wait):
        sys.stdout.write(buf.decode(errors="replace")); print("\nMISSING " + wait); os.kill(pid, 9); os.waitpid(pid, 0); sys.exit(0)
    buf = buf.replace(wait.encode(), b"<" + wait.encode() + b">", 1)
    time.sleep(0.3); os.write(fd, send.encode())
end = time.time() + 20
while time.time() < end:
    r, _, _ = select.select([fd], [], [], 0.1)
    if r:
        try: d = os.read(fd, 4096)
        except OSError: break
        if not d: break
        buf += d
st = None
for _ in range(100):
    p, st = os.waitpid(pid, os.WNOHANG)
    if p: break
    time.sleep(0.1)
else:
    os.kill(pid, 9); _, st = os.waitpid(pid, 0); buf += b"\nKILLED: still running"
sys.stdout.write(buf.decode(errors="replace")); print("\nEXIT %d" % os.waitstatus_to_exitcode(st))
`;

test("Ctrl-C during custosa login stops the sign-in in a cooked terminal, and setup goes on", { skip: !HAS_PTY && "needs python3 with pty" }, async () => {
  const s = await stub((call) => (call.url === "/v1/device/start"
    ? { status: 200, json: { device_code: "devcode_ABCDEFGHIJKLMNOP", user_code: "WDJB-MJHT", verification_uri: "https://auth.custosa.com/device",
      verification_uri_complete: "https://auth.custosa.com/device?code=WDJB-MJHT", expires_in: 600, interval: 1 } }
    : { status: 400, json: { error: "authorization_pending" } }));
  try {
    const home = mkdtempSync(join(tmpdir(), "custosa-pty-"));
    mkdirSync(join(home, ".cursor"));
    const driver = join(home, "driver.py");
    writeFileSync(driver, DRIVER);
    const env = { PATH: process.env.PATH, HOME: home, CUSTOSA_CONFIG_DIR: join(home, "cfg"), CUSTOSA_EVALUATOR_URL: s.url, NO_COLOR: "1", PGSERVICEFILE: join(home, "none.conf") };
    const steps = [["Add PHI Schema Check to Cursor?", "\r"], ["Sign in to PHI Schema Check now?", "\r"], ["Waiting for you to approve", "\x03"], ["> ", "\r"]];
    const child = spawn("python3", [driver, JSON.stringify(steps), JSON.stringify([process.execPath, BIN, "setup", "--client", "cursor"])], { env });
    let text = "";
    child.stdout.on("data", (d) => { text += d; });
    await new Promise((ok) => child.on("close", ok));
    assert.doesNotMatch(text, /MISSING/, text);
    assert.match(text, /EXIT 0/, text);
    assert.match(text, /Sign in  Run npx custosa login in a terminal/, text);
    assert.match(text, /Environment  marked unknown/, text);
    assert.doesNotMatch(text, /\^C.*\n.*Waiting/, "the sign-in stopped at Ctrl-C");
  } finally { await s.close(); }
});

test("when custosa login can't show the evaluator's sign-in page (not on the allowlist), setup says sign-in isn't available yet", { skip: !HAS_PTY && "needs python3 with pty" }, async () => {
  const s = await stub((call) => (call.url === "/v1/device/start"
    ? { status: 200, json: { device_code: "devcode_ABCDEFGHIJKLMNOP", user_code: "WDJB-MJHT", verification_uri: "https://login.example.test/device",
      verification_uri_complete: "https://login.example.test/device?code=WDJB-MJHT", expires_in: 600, interval: 1 } }
    : { status: 400, json: { error: "authorization_pending" } }));
  try {
    const home = mkdtempSync(join(tmpdir(), "custosa-pty-"));
    mkdirSync(join(home, ".cursor"));
    const driver = join(home, "driver.py");
    writeFileSync(driver, DRIVER);
    const env = { PATH: process.env.PATH, HOME: home, CUSTOSA_CONFIG_DIR: join(home, "cfg"), CUSTOSA_EVALUATOR_URL: s.url, NO_COLOR: "1", PGSERVICEFILE: join(home, "none.conf") };
    const steps = [["Add PHI Schema Check to Cursor?", "\r"], ["Sign in to PHI Schema Check now?", "\r"], ["isn’t available yet", ""], ["> ", "\r"]];
    const child = spawn("python3", [driver, JSON.stringify(steps), JSON.stringify([process.execPath, BIN, "setup", "--client", "cursor"])], { env });
    let text = "";
    child.stdout.on("data", (d) => { text += d; });
    await new Promise((ok) => child.on("close", ok));
    assert.doesNotMatch(text, /MISSING/, text);
    assert.match(text, /EXIT 0/, text);
    assert.match(text, /Sign in  PHI Schema Check sign-in <?isn’t available yet>?\. Try again later with npx custosa login\./, text);
    assert.equal(s.calls.filter((c) => c.url === "/v1/device/poll").length, 0, "nothing polled");
  } finally { await s.close(); }
});
