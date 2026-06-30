// Sealing binds a bundle to an issuer signature and a transparency receipt.
//
// Two canonical projections keep signing and logging non-circular:
//   core  = bundle with signature="" and receipt=null  (what the issuer signs)
//   leaf  = bundle with receipt=null (signature kept)   (what the log records)
// Both sides recompute these identically, so bytes match without field deletion.
import type { AdmissionBundle } from "./types";
import { canonicalBytes } from "../canonical";
import { signBytes } from "../crypto";
import { leafHash, TransparencyLog } from "../merkle";

export function clone<T>(x: T): T {
  return JSON.parse(JSON.stringify(x)) as T;
}

export function coreClone(b: AdmissionBundle): AdmissionBundle {
  const c = clone(b);
  c.issuance.signature = "";
  c.issuance.transparencyReceipt = null;
  return c;
}

export function leafClone(b: AdmissionBundle): AdmissionBundle {
  const c = clone(b);
  c.issuance.transparencyReceipt = null;
  return c;
}

// Sign with the issuer key, append to the transparency log, attach the receipt
// (whose root is signed by the log key). Mutates and returns the bundle.
export function seal(
  bundle: AdmissionBundle,
  issuerPrivateKeyPem: string,
  log: TransparencyLog,
  logPrivateKeyPem: string,
): AdmissionBundle {
  bundle.issuance.signature = signBytes(
    canonicalBytes(coreClone(bundle)),
    issuerPrivateKeyPem,
  );
  bundle.issuance.transparencyReceipt = null;

  const appended = log.append(canonicalBytes(leafClone(bundle)));
  const rootSignature = signBytes(
    Buffer.from(appended.rootHash, "hex"),
    logPrivateKeyPem,
  );

  bundle.issuance.transparencyReceipt = {
    logId: log.id,
    treeSize: appended.treeSize,
    leafIndex: appended.leafIndex,
    auditPath: appended.auditPath,
    rootHash: appended.rootHash,
    rootSignature,
  };
  return bundle;
}
