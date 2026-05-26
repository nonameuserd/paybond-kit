declare module "node:crypto" {
  type Hash = {
    update(data: Uint8Array): Hash;
    digest(): Uint8Array;
  };

  export function createHash(algorithm: string): Hash;
}
