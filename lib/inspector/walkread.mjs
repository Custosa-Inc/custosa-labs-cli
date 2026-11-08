/* Reading a file the walk listed: through files.assertInside (a regular file, no symlink, its realpath inside the
 * root), then the open handle's dev and ino compared with the checked ones, so a swap between the check and the open
 * is refused. An env-named file is refused unless the caller asks for one with envName: true, which only the secret
 * scan does, and only for an env file git tracks.
 *
 * readWalked(root, rel, maxBytes, {envName}) -> {buf} | {refused: "too_large" | "unreadable"} */
import { open } from "node:fs/promises";
import { assertInside, isEnvFile } from "./files.mjs";

export async function readWalked(root, rel, maxBytes, { envName = false } = {}) {
  const base = rel.slice(rel.lastIndexOf("/") + 1);
  if (isEnvFile(base) && envName !== true) return { refused: "unreadable" };
  let handle;
  try {
    const checked = await assertInside(root, rel);
    if (checked.size > maxBytes) return { refused: "too_large" };
    handle = await open(checked.abs, "r");
    const st = await handle.stat();
    if (!st.isFile() || st.dev !== checked.dev || st.ino !== checked.ino) return { refused: "unreadable" };
    if (st.size > maxBytes) return { refused: "too_large" };
    const buf = Buffer.alloc(Math.min(st.size, maxBytes) + 1);
    let n = 0;
    for (;;) {
      const { bytesRead } = await handle.read(buf, n, buf.length - n, n);
      if (bytesRead === 0) break;
      n += bytesRead;
      if (n >= buf.length) return { refused: "too_large" };
    }
    return { buf: buf.subarray(0, n) };
  } catch {
    return { refused: "unreadable" };
  } finally {
    await handle?.close().catch(() => {});
  }
}
