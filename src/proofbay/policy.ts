// Helpers for reasoning over CSP policy strings of the form
// "<directive> <https-origin>", e.g. "connect-src https://api.stripe.com".

export function policyHosts(csp: string[]): Set<string> {
  const hosts = new Set<string>();
  for (const entry of csp) {
    const url = entry.split(/\s+/)[1];
    if (url) {
      try {
        hosts.add(new URL(url).host);
      } catch {
        /* ignore malformed entries */
      }
    }
  }
  return hosts;
}

export function grantParts(grant: string): { directive: string; url: string } {
  const i = grant.indexOf(" ");
  if (i < 0) return { directive: grant, url: "" };
  return { directive: grant.slice(0, i), url: grant.slice(i + 1) };
}
