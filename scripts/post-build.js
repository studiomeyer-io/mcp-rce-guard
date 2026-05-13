#!/usr/bin/env node
// Post-build: prepend shebang to dist/cli.js + dist/server.js, set exec-bit.
import { readFileSync, writeFileSync, chmodSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const distDir = resolve(__dirname, "..", "dist");

const shebang = "#!/usr/bin/env node\n";
const targets = ["cli.js", "server.js"];

for (const target of targets) {
  const path = resolve(distDir, target);
  if (!existsSync(path)) {
    console.error(`[post-build] skip ${target}: not found`);
    continue;
  }
  let content = readFileSync(path, "utf8");
  if (!content.startsWith("#!/usr/bin/env node")) {
    content = shebang + content;
    writeFileSync(path, content, "utf8");
  }
  chmodSync(path, 0o755);
  console.log(`[post-build] ${target}: shebang + chmod 755`);
}
