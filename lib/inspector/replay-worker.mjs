/* The migration replay's worker thread (T29 gap 2, T29-P1-C562): replay.mjs starts it, times it and ends it. It runs
 * the engine (replay-engine.mjs) on the data replay.mjs built, with no hooks: the engine's test setup is reachable
 * only from a test's own worker (T29-P3-C664 low 3). */
import { parentPort, workerData } from "node:worker_threads";
import { runReplay } from "./replay-engine.mjs";

runReplay(workerData, (m) => parentPort.postMessage(m));
