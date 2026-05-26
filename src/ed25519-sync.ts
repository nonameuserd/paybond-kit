import { createHash } from "node:crypto";
import { etc } from "@noble/ed25519";

export function ensureEd25519Sha512Sync(): void {
  if (etc.sha512Sync) {
    return;
  }
  etc.sha512Sync = (...messages: Uint8Array[]): Uint8Array => {
    const hash = createHash("sha512");
    for (const message of messages) {
      hash.update(message);
    }
    return new Uint8Array(hash.digest());
  };
}
