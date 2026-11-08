/* The copy the CLI shares with the setup page: shared.json is a byte-for-byte copy of the website's
   web/src/lib/labs/shared.json (checked by the website's tests). Read as a file so Node 18.17 needs no JSON import. */
import { readFileSync } from "node:fs";

export const SHARED = JSON.parse(readFileSync(new URL("./shared.json", import.meta.url), "utf8"));
