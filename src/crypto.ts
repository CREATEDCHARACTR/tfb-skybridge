// Zero-dependency crypto over node:crypto. Ed25519 signatures, sha256 hashing.
import {
  createHash,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
  createPublicKey,
  createPrivateKey,
} from "node:crypto";

export function sha256(data: Buffer | string): Buffer {
  const buf = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  return createHash("sha256").update(buf).digest();
}

export function sha256Hex(data: Buffer | string): string {
  return sha256(data).toString("hex");
}

export interface KeyPair {
  publicKeyPem: string;
  privateKeyPem: string;
}

export function generateKeyPair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

export function signBytes(data: Buffer, privateKeyPem: string): string {
  const key = createPrivateKey(privateKeyPem);
  return nodeSign(null, data, key).toString("base64");
}

export function verifyBytes(
  data: Buffer,
  signatureB64: string,
  publicKeyPem: string,
): boolean {
  try {
    const key = createPublicKey(publicKeyPem);
    return nodeVerify(null, data, key, Buffer.from(signatureB64, "base64"));
  } catch {
    return false;
  }
}
