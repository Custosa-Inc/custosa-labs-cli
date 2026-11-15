/* secrets.mjs loadInstallKey: the install key that is already there and can't be used, and the races around making a
 * new one. A short or long key file, a key that can't be opened or read, a key or folder of another user, and a link
 * that lost to another run ran in no test (readKey lines 179 to 204, checkDir 163 and 170, lines 260 to 267).
 * Failures are injected through options.fsOverrides, the module's own test hook. Every config dir is a temp folder. */
import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const { mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, symlinkSync, writeFileSync } = fs;
const temp = () => realpathSync(mkdtempSync(join(tmpdir(), "t19-install-key-")));
process.env.CUSTOSA_CONFIG_DIR = temp();

const { loadInstallKey, InstallKeyError } = await import("../lib/inspector/secrets.mjs");

const win = process.platform === "win32";
const errno = (code) => Object.assign(new Error(code), { code });
/* A config dir holding install.key with these bytes, 0600. */
function withKey(bytes) {
  const configDir = temp();
  writeFileSync(join(configDir, "install.key"), bytes, { mode: 0o600 });
  return configDir;
}
const refused = (re) => (err) => err instanceof InstallKeyError && re.test(err.message);

test("a key file that is not 32 bytes is refused and left as it is, never replaced", () => {
  for (const n of [0, 1, 31, 33, 64]) {
    const bytes = Buffer.alloc(n, 9);
    const configDir = withKey(bytes);
    assert.throws(() => loadInstallKey({ configDir }), refused(/is not a 32-byte key\. Delete it to create a new one/),
      `${n} bytes`);
    assert.deepEqual(readFileSync(join(configDir, "install.key")), bytes, `${n} bytes`);
    assert.deepEqual(readdirSync(configDir), ["install.key"], `${n} bytes`);
  }
  assert.deepEqual(loadInstallKey({ configDir: withKey(Buffer.alloc(32, 9)) }), Buffer.alloc(32, 9));
});

test("an install.key that is a link or a folder is refused, even when the link points at a good key", { skip: win }, () => {
  const good = withKey(Buffer.alloc(32, 5));
  const linked = temp();
  symlinkSync(join(good, "install.key"), join(linked, "install.key"));
  assert.throws(() => loadInstallKey({ configDir: linked }), refused(/is not a regular file/));
  const folder = temp();
  mkdirSync(join(folder, "install.key"));
  assert.throws(() => loadInstallKey({ configDir: folder }), refused(/is not a regular file/));
});

test("a config dir that is a file is refused", () => {
  const file = join(temp(), "custosa");
  writeFileSync(file, "");
  assert.throws(() => loadInstallKey({ configDir: file }), refused(/it is not a directory/));
});

test("a key that can't be looked at, opened or read is an error naming why, never a new key", () => {
  const bytes = Buffer.alloc(32, 3);
  for (const [fn, code] of [["lstatSync", "EACCES"], ["openSync", "EACCES"], ["readSync", "EIO"]]) {
    const configDir = withKey(bytes);
    const closed = [];
    const fsOverrides = {
      [fn]: () => { throw errno(code); },
      closeSync: (fd) => { closed.push(fd); fs.closeSync(fd); },
    };
    assert.throws(() => loadInstallKey({ configDir, fsOverrides }),
      refused(new RegExp(`^Cannot read the install key .*install\\.key: ${code}\\.$`)), fn);
    assert.deepEqual(readFileSync(join(configDir, "install.key")), bytes, fn);
    assert.deepEqual(readdirSync(configDir), ["install.key"], fn);
    // Once a descriptor is open it is closed on the way out.
    assert.equal(closed.length, fn === "readSync" ? 1 : 0, fn);
  }
  // A config dir that can't be looked at (not missing) is an error too, and nothing is made in it.
  const configDir = temp();
  assert.throws(() => loadInstallKey({ configDir, fsOverrides: { statSync: () => { throw errno("EACCES"); } } }),
    refused(/^Cannot read the config dir .*: EACCES\.$/));
  assert.deepEqual(readdirSync(configDir), []);
});

test("the open descriptor is checked again: a key that turned readable or changed owner after lstat is refused",
  { skip: win }, () => {
    const configDir = withKey(Buffer.alloc(32, 4));
    const fstatAs = (change) => ({ fstatSync: (fd) => Object.assign(fs.fstatSync(fd), change(fs.fstatSync(fd))) });
    assert.throws(() => loadInstallKey({ configDir, fsOverrides: fstatAs((st) => ({ mode: st.mode | 0o044 })) }),
      refused(/group or world readable \(mode 644\)/));
    assert.throws(() => loadInstallKey({ configDir, fsOverrides: fstatAs((st) => ({ uid: st.uid + 1 })) }),
      refused(/is owned by another user/));
    assert.deepEqual(loadInstallKey({ configDir }), Buffer.alloc(32, 4));
  });

test("a config dir of another user is refused", { skip: win || typeof process.getuid !== "function" }, () => {
  const configDir = withKey(Buffer.alloc(32, 6));
  const statSync = (p, ...rest) => {
    const st = fs.statSync(p, ...rest);
    return p === configDir ? Object.assign(st, { uid: st.uid + 1 }) : st;
  };
  assert.throws(() => loadInstallKey({ configDir, fsOverrides: { statSync } }), refused(/is owned by another user/));
});

test("a close that fails after a good read still returns the key", () => {
  const configDir = withKey(Buffer.alloc(32, 8));
  const key = loadInstallKey({ configDir, fsOverrides: { closeSync: () => { throw errno("EIO"); } } });
  assert.deepEqual(key, Buffer.alloc(32, 8));
});

test("a run that loses the race to link the key uses the key the other run made", () => {
  const theirs = Buffer.alloc(32, 1);
  // Hard link: another run linked its key first, so ours fails with EEXIST.
  const linked = temp();
  const linkSync = (_tmp, path) => { writeFileSync(path, theirs, { mode: 0o600 }); throw errno("EEXIST"); };
  assert.deepEqual(loadInstallKey({ configDir: linked, fsOverrides: { linkSync } }), theirs);
  assert.deepEqual(readdirSync(linked), ["install.key"]);
  // No hard links: the O_EXCL write to the final name finds the other run's key there.
  const nolink = temp();
  const openSync = (path, flags, ...rest) => {
    if (flags === "wx" && path === join(nolink, "install.key")) writeFileSync(path, theirs, { mode: 0o600 });
    return fs.openSync(path, flags, ...rest);
  };
  const linkFails = () => { throw errno("EPERM"); };
  assert.deepEqual(loadInstallKey({ configDir: nolink, fsOverrides: { linkSync: linkFails, openSync } }), theirs);
  assert.deepEqual(readdirSync(nolink), ["install.key"]);
});

test("a new key that is not there after the link is an error, and the temp file is still removed", () => {
  const configDir = temp();
  assert.throws(() => loadInstallKey({ configDir, fsOverrides: { linkSync: () => {} } }),
    refused(/^Cannot create the install key .*install\.key\.$/));
  assert.deepEqual(readdirSync(configDir), []);
  // A link that fails for another reason names it, and leaves nothing behind.
  const other = temp();
  assert.throws(() => loadInstallKey({ configDir: other, fsOverrides: { linkSync: () => { throw errno("EIO"); } } }),
    refused(/^Cannot create the install key .*: EIO\.$/));
  assert.deepEqual(readdirSync(other), []);
  // Without hard links, a write to the final name that fails for another reason names it too.
  const nolink = temp();
  const fsOverrides = {
    linkSync: () => { throw errno("ENOTSUP"); },
    openSync: (path, flags, ...rest) => {
      if (flags === "wx" && path === join(nolink, "install.key")) throw errno("ENOSPC");
      return fs.openSync(path, flags, ...rest);
    },
  };
  assert.throws(() => loadInstallKey({ configDir: nolink, fsOverrides }), refused(/: ENOSPC\.$/));
  assert.deepEqual(readdirSync(nolink), []);
});
