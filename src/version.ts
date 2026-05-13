/**
 * Read the version from package.json at runtime so tests + server + CLI
 * never drift from the actual published version.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
// dist/version.js -> ../package.json
const pkgPath = join(here, "..", "package.json");

interface PkgJson {
  name: string;
  version: string;
}

const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as PkgJson;

export const NAME = pkg.name;
export const VERSION = pkg.version;
