import { writeSync } from "node:fs";
import { ShadowExtractionObserver } from "../../src/behavior/extraction/shadow";

const observer = new ShadowExtractionObserver();
const observed = observer.observe({
  tenantToken: "0000000000000001",
  sessionToken: "0000000000000002",
  sequence: "0000000000000001",
  querySimhash: "0000000000000003",
  regionToken: "0000000000000004",
});
writeSync(1, `${JSON.stringify({ observed, retention: observer.retentionStatus() })}\n`);
process.exit(23);
