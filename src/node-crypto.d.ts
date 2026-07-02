declare module "node:crypto" {
  type BinaryLike = string | ArrayBufferView;
  type BinaryToTextEncoding = "hex" | "base64" | "base64url" | "latin1" | "binary";

  type Hash = {
    update(data: BinaryLike, inputEncoding?: BufferEncoding): Hash;
    digest(): Uint8Array;
    digest(encoding: BinaryToTextEncoding): string;
  };

  export function createHash(algorithm: string): Hash;
  export function randomUUID(): string;
}
