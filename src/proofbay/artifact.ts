// The artifact is the exact view bundle that renders inside the iframe,
// modeled as a content-addressed set of files. Witnesses cite byte spans;
// the verifier re-hashes those spans to confirm the evidence is really present.
import { sha256Hex } from "../crypto";
import { canonicalize } from "../canonical";

export type Artifact = Map<string, Buffer>;

export function artifactHash(artifact: Artifact): string {
  const manifest = [...artifact.keys()]
    .sort()
    .map((name) => [name, sha256Hex(artifact.get(name)!)]);
  return sha256Hex(canonicalize(manifest));
}

export function sliceHash(
  artifact: Artifact,
  file: string,
  span: [number, number],
): string | null {
  const buf = artifact.get(file);
  if (!buf) return null;
  const [start, end] = span;
  if (start < 0 || end > buf.length || start > end) return null;
  return sha256Hex(buf.subarray(start, end));
}
