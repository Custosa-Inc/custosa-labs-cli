/* Which folders may be a project root. The inspector reads every file under its root, so a root that is the
 * whole disk, the home folder or a folder of many projects would be read in full on every check. Refused:
 *   - a filesystem root (/, C:\);
 *   - the home folder, or a folder above it;
 *   - a folder that isn't in a git repository and holds one somewhere below it (a folder of projects).
 * A folder in a repository (the repository's root or a folder inside it) is a project. A plain folder that is none of
 * the refused kinds is allowed, and its walk stays bounded by the walker's caps and the check's time budget.
 *
 * projectRootProblem(abs, {home}) -> null | {code, message}. Reads directory listings only (findGitRoot looks for a
 * .git entry at or above the folder; nestedRepos lists folders below it, capped); never opens a file. */
import { lstat, realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { nestedRepos } from "./factdoc.mjs";

const OPEN = "Open the assistant (or run the command) in the project's own folder, the repository of one app, and try again.";
export const ROOT_PROBLEMS = Object.freeze({
  filesystem_root: `custosa inspect: refused to inspect a filesystem root as the project: it would read the whole disk. ${OPEN}`,
  home_folder: `custosa inspect: refused to inspect your home folder as the project: it would read every file in it. ${OPEN}`,
  above_home: `custosa inspect: refused to inspect a folder above your home folder as the project: it would read every file in it. ${OPEN}`,
  above_repositories: `custosa inspect: refused to inspect this folder as the project: it isn't a git repository and holds other repositories, so it looks like a folder of projects. ${OPEN}`,
});

const isAncestor = (a, b) => b.startsWith(a.endsWith(sep) ? a : a + sep);

/* The nearest folder at or above `start` holding a .git entry, or null (nothing inside it is read). */
async function gitRootOf(start) {
  let dir = resolve(start);
  for (;;) {
    try { await lstat(join(dir, ".git")); return dir; } catch { /* not here */ }
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

export async function projectRootProblem(abs, { home = homedir() } = {}) {
  const problem = (code) => ({ code, message: ROOT_PROBLEMS[code] });
  let real = resolve(abs);
  try { real = await realpath(abs); } catch { /* judged as given */ }
  if (dirname(real) === real) return problem("filesystem_root");
  let realHome = home ? resolve(home) : null;
  if (realHome) { try { realHome = await realpath(realHome); } catch { /* as given */ } }
  if (realHome && real === realHome) return problem("home_folder");
  if (realHome && isAncestor(real, realHome)) return problem("above_home");
  const repo = await gitRootOf(real);
  // In a repository (one that isn't the home folder or the disk itself, as a dotfiles repository can be): a project.
  if (repo && repo !== realHome && dirname(repo) !== repo) return null;
  const inner = await nestedRepos(real, { maxDirs: 5_000, maxRepos: 1 });
  if (inner.repos.length) return problem("above_repositories");
  return null;
}
