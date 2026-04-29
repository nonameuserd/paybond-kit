import { readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = new URL("..", import.meta.url);
const rootPath = fileURLToPath(root);

for (const relative of ["dist"]) {
  rmSync(new URL(relative, root), { force: true, recursive: true });
}

for (const entry of readdirSync(root, { withFileTypes: true })) {
  if (entry.isFile() && entry.name.endsWith(".tgz")) {
    rmSync(join(rootPath, entry.name), { force: true });
  }
}
