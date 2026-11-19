export function renderDrawbridgeConsole(): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TFB Drawbridge Control Room</title>
<style>
:root{--ink:#171813;--ivory:#f1eadb;--paper:#d9ceb9;--oxide:#d65d43;--steel:#8f9a8f}
*{box-sizing:border-box}body{margin:0;background:var(--ink);color:var(--ivory);font-family:Georgia,"Times New Roman",serif;min-height:100vh;background-image:linear-gradient(rgba(241,234,219,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(241,234,219,.035) 1px,transparent 1px);background-size:28px 28px}
header{display:grid;grid-template-columns:1fr auto;align-items:end;padding:32px 5vw 22px;border-bottom:2px solid var(--oxide)}h1{margin:0;font:700 clamp(2rem,5vw,5rem)/.85 Impact,Haettenschweiler,"Arial Narrow Bold",sans-serif;letter-spacing:.025em;text-transform:uppercase}.tag{font:700 .75rem/1.1 ui-monospace,monospace;letter-spacing:.18em;color:var(--oxide)}
main{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(290px,.7fr);gap:24px;padding:28px 5vw 64px}.deck,.rail{border:1px solid var(--steel);background:rgba(23,24,19,.92);box-shadow:10px 10px 0 #0b0c09}.deck{padding:28px}.rail{padding:20px;align-self:start}.signal{display:inline-block;border:1px solid var(--oxide);color:var(--oxide);padding:8px 12px;font:800 .72rem ui-monospace,monospace;letter-spacing:.14em}.signal::before{content:"●";margin-right:8px}.label{display:block;margin:25px 0 8px;color:var(--paper);font:700 .72rem ui-monospace,monospace;letter-spacing:.13em;text-transform:uppercase}h2.label{font-size:.72rem}textarea,select{width:100%;background:#0f100d;border:1px solid var(--steel);color:var(--ivory);padding:14px;font:1rem/1.5 Georgia,serif}textarea{min-height:150px;resize:vertical}button{margin-top:16px;background:var(--oxide);color:var(--ink);border:0;padding:14px 18px;font:900 .78rem ui-monospace,monospace;letter-spacing:.12em;text-transform:uppercase;cursor:pointer}button.secondary{margin-left:8px;background:transparent;color:var(--ivory);border:1px solid var(--steel)}button:hover{filter:brightness(1.18)}button:focus-visible,textarea:focus-visible,select:focus-visible{outline:3px solid var(--paper);outline-offset:3px}button:disabled{cursor:wait;filter:grayscale(.7);opacity:.65}button[hidden]{display:none}dl{display:grid;grid-template-columns:1fr;gap:14px}dt{font:700 .68rem ui-monospace,monospace;color:var(--steel);letter-spacing:.12em;text-transform:uppercase}dd{margin:4px 0 0;font:700 .9rem ui-monospace,monospace;overflow-wrap:anywhere}.oxide{color:var(--oxide)}#response{white-space:pre-wrap;border-left:4px solid var(--oxide);padding:14px 18px;background:#10110e;min-height:80px}.fine{color:var(--paper);font-size:.8rem;line-height:1.5}@media(max-width:800px){main{grid-template-columns:1fr}header{grid-template-columns:1fr;gap:16px}.deck{padding:20px}.rail{padding:18px}button{width:100%}button.secondary{margin-left:0}}
</style></head><body>
<header><div><div class="tag">TFB / PRODUCT OBSERVATORY</div><h1>Drawbridge<br>Control Room</h1></div><span class="signal">OBSERVE ONLY</span></header>
<main><section class="deck" aria-labelledby="crossing-heading"><p class="fine">ChatGPT agent stand-in · external request/response exchange · no local model · no provider network call</p><h2 id="crossing-heading" class="label">Bounded crossing</h2><label class="label" for="prompt">Prompt crossing</label><textarea id="prompt" placeholder="Place one bounded prompt on the bridge..."></textarea><label class="label" for="scenario">Accountable region evidence</label><select id="scenario"><option value="">Loading frozen scenarios…</option></select><button id="submit" type="button" disabled>Open crossing</button><button id="retry-pending" class="secondary" type="button" hidden>Retry pending crossing</button><button id="new-session" class="secondary" type="button" hidden>Start new local session</button><button id="erase-session" class="secondary" type="button" hidden>Erase local session</button><h2 id="agent-response-heading" class="label">Agent response</h2><div id="response" role="region" aria-labelledby="agent-response-heading">Waiting for a crossing.</div></section>
<aside class="rail" aria-label="Drawbridge receipt status"><div id="status-region" role="status" aria-live="polite" aria-atomic="false"><dl><div><dt>Runtime</dt><dd>ChatGPT agent stand-in</dd></div><div><dt>Authority</dt><dd class="oxide">OBSERVE ONLY</dd></div><div><dt>Crossing state</dt><dd id="state">INITIALIZING</dd></div><div><dt>Request</dt><dd id="request">None</dd></div><div><dt>Assessment</dt><dd id="assessment">Not observed</dd></div><div><dt>Reason</dt><dd id="reason">No observation yet</dd></div><div><dt>Receipt reference</dt><dd id="receipt">None</dd></div><div><dt>Attestation</dt><dd id="attestation">NOT_CONFIGURED</dd></div><div><dt>Evidence boundary</dt><dd>Synthetic demo evidence</dd></div></dl></div><p class="fine">Synthetic region fixtures demonstrate the pipeline only. They do not establish real-world extraction behavior, production readiness, or enforcement authority.</p></aside></main>
<script type="module" src="/drawbridge.js"></script></body></html>`;
}

export function renderDrawbridgeBrowserScript(): string {
  return `const byId=(id)=>document.getElementById(id);
const prompt=byId("prompt"),scenario=byId("scenario"),submit=byId("submit");
const retryPending=byId("retry-pending"),newSession=byId("new-session"),eraseSession=byId("erase-session");
const state=byId("state"),requestRef=byId("request"),response=byId("response");
const assessment=byId("assessment"),reason=byId("reason"),receipt=byId("receipt"),attestation=byId("attestation");
const STORAGE={identity:"tfb.drawbridge.browser_session_identity.v1",ref:"tfb.drawbridge.browser_session_ref.v1",resumeToken:"tfb.drawbridge.browser_session_resume_token.v1"};
const CAPABILITY=/^[0-9a-f]{64}$/;
const MAX_POLL_ATTEMPTS=330;
const BROWSER_REQUEST_TIMEOUT_MS=10000;
let sessionIdentity=null,sessionRef=null,sessionCapability=null,sessionResumeToken=null,activePendingRequestId=null;
let pollTimer=null,pollAttempts=0,pageClosed=false,capabilityBlocked=false,resumeWasRequested=false;
const inflightRequests=new Set();
const syntheticDemoOnly=true;
async function json(path,options={}){
  const controller=new AbortController();
  inflightRequests.add(controller);
  const deadline=setTimeout(()=>controller.abort(new Error("browser_request_deadline_exceeded")),BROWSER_REQUEST_TIMEOUT_MS);
  try{
    const reply=await fetch(path,{...options,signal:controller.signal,headers:{"content-type":"application/json",...(options.headers||{})}});
    let body;
    try{body=await reply.json();}catch{throw new Error("response_json_invalid");}
    return {status:reply.status,body};
  }finally{
    clearTimeout(deadline);
    inflightRequests.delete(controller);
  }
}
function authHeaders(){
  if(!CAPABILITY.test(sessionCapability||""))throw new Error("session_capability_unavailable");
  return {"x-drawbridge-session-capability":sessionCapability};
}
function authorizedJson(path,options={}){
  return json(path,{...options,headers:{...authHeaders(),...(options.headers||{})}});
}
function hasStoredSessionEvidence(){
  return Boolean(sessionStorage.getItem(STORAGE.identity)||sessionStorage.getItem(STORAGE.ref)||sessionStorage.getItem(STORAGE.resumeToken));
}
function storedSession(){
  const identity=sessionStorage.getItem(STORAGE.identity);
  const ref=sessionStorage.getItem(STORAGE.ref);
  const resumeToken=sessionStorage.getItem(STORAGE.resumeToken);
  if(!identity&&!ref&&!resumeToken)return null;
  if(!identity||!CAPABILITY.test(ref||"")||!CAPABILITY.test(resumeToken||"")){
    clearStoredSession();
    throw new Error("browser_session_storage_contract_invalid");
  }
  return {identity,ref,resumeToken};
}
function saveStoredSession(identity,ref,resumeToken){
  sessionStorage.setItem(STORAGE.identity,identity);
  sessionStorage.setItem(STORAGE.ref,ref);
  sessionStorage.setItem(STORAGE.resumeToken,resumeToken);
}
function clearStoredSession(){
  sessionStorage.removeItem(STORAGE.identity);
  sessionStorage.removeItem(STORAGE.ref);
  sessionStorage.removeItem(STORAGE.resumeToken);
  sessionIdentity=null;sessionRef=null;sessionCapability=null;sessionResumeToken=null;activePendingRequestId=null;
  retryPending.hidden=true;
}
function bindSession(identity,body){
  if(!body?.ok||!CAPABILITY.test(body.sessionRef||"")||!CAPABILITY.test(body.sessionCapability||"")||!CAPABILITY.test(body.sessionResumeToken||"")){
    throw new Error("session_response_contract_invalid");
  }
  sessionIdentity=identity;
  sessionRef=body.sessionRef;
  sessionCapability=body.sessionCapability;
  sessionResumeToken=body.sessionResumeToken;
  saveStoredSession(identity,sessionRef,sessionResumeToken);
  eraseSession.hidden=false;
}
function failureText(body){
  const values=body?.holds||body?.errors;
  return Array.isArray(values)&&values.length?values.join(", "):"unknown_hold";
}
function errorText(error){return error&&typeof error.message==="string"?error.message:String(error);}
function isCapabilityFailure(status,body){
  if(status===401||status===403)return true;
  const holds=Array.isArray(body?.holds)?body.holds:[];
  return holds.some((value)=>String(value).startsWith("session_resume_token_")||String(value).startsWith("session_capability_"));
}
function hasHold(body,value){return Array.isArray(body?.holds)&&body.holds.includes(value);}
function cancelPoll(){if(pollTimer!==null)clearTimeout(pollTimer);pollTimer=null;}
function setFailure(body,{capability=false,blockJourney=capability}={}){
  cancelPoll();
  state.textContent="HELD";
  reason.textContent=failureText(body);
  retryPending.hidden=true;
  if(blockJourney){
    if(capability)clearStoredSession();
    capabilityBlocked=true;
    submit.disabled=true;
    newSession.hidden=false;
    eraseSession.hidden=true;
  }else submit.disabled=false;
}
function setPendingFailure(requestId,body){
  cancelPoll();
  activePendingRequestId=requestId;
  state.textContent="HELD · PENDING_RETRY";
  requestRef.textContent=requestId;
  reason.textContent=failureText(body);
  response.textContent="The durable pending request was retained. Retry this same crossing before opening another.";
  submit.disabled=true;
  retryPending.hidden=false;
}
async function loadRegions(){
  const {body}=await json("/api/regions");
  if(!body?.ok||!Array.isArray(body.regions))throw new Error(failureText(body));
  scenario.replaceChildren();
  for(const item of body.regions){
    const option=document.createElement("option");
    option.value=item.scenarioId;
    option.textContent=item.scenarioId+" · frozen synthetic fixture";
    scenario.append(option);
  }
}
function projectAttestation(value){attestation.textContent=typeof value==="string"&&value?value:"NOT_CONFIGURED";}
function latestBySequence(items){
  return items.reduce((latest,item)=>{
    if(!latest)return item;
    const itemSequence=Number.isSafeInteger(item?.sequence)?item.sequence:-1;
    const latestSequence=Number.isSafeInteger(latest?.sequence)?latest.sequence:-1;
    return itemSequence>latestSequence?item:latest;
  },null);
}
function projectStatus(body){
  const pending=Array.isArray(body.pending)?body.pending:[];
  const receipts=Array.isArray(body.receipts)?body.receipts:[];
  const latest=latestBySequence(receipts);
  const oldestPending=pending[0]||null;
  const advertised=body.actionablePendingRequestId;
  if(pending.some((item)=>!Number.isSafeInteger(item?.sequence)))throw new Error("session_status_pending_order_invalid");
  for(let index=1;index<pending.length;index++){
    if(pending[index-1].sequence>=pending[index].sequence){
      throw new Error("session_status_pending_order_invalid");
    }
  }
  if(oldestPending){
    if(!CAPABILITY.test(oldestPending.requestId||"")||(advertised!==undefined&&advertised!==oldestPending.requestId)){
      throw new Error("session_status_actionable_pending_mismatch");
    }
    activePendingRequestId=oldestPending.requestId;
    retryPending.hidden=true;
    submit.disabled=true;
    state.textContent="RESUMED · PENDING_AGENT_RESPONSE";
    requestRef.textContent=oldestPending.requestId;
    assessment.textContent="Not observed";
    reason.textContent="Awaiting the ChatGPT agent stand-in response.";
    receipt.textContent="None";
    projectAttestation(null);
    response.textContent="A bounded request is pending the ChatGPT agent stand-in.";
    return oldestPending.requestId;
  }
  if(advertised!==undefined&&advertised!==null)throw new Error("session_status_actionable_pending_mismatch");
  activePendingRequestId=null;
  retryPending.hidden=true;
  if(latest){
    state.textContent="RESUMED · NEXT "+String(body.nextSequence??"?");
    requestRef.textContent=latest.requestId||"None";
    assessment.textContent=latest.assessment?.status||"Not observed";
    reason.textContent=latest.assessment?.reason||"No reason supplied";
    receipt.textContent=latest.receiptReference||"None";
    projectAttestation(latest.attestationReference);
    response.textContent="Raw response was not retained; showing the durable redacted receipt.";
  }else{
    state.textContent="RESUMED · NEXT "+String(body.nextSequence??1);
    requestRef.textContent="None";
    assessment.textContent="Not observed";
    reason.textContent="No observation yet";
    receipt.textContent="None";
    projectAttestation(null);
    response.textContent="Durable session resumed. No retained raw response.";
  }
  return null;
}
async function resumeStoredSession(){
  const stored=storedSession();
  if(!stored)return false;
  resumeWasRequested=true;
  state.textContent="RESUMING";
  const resumed=await json("/api/sessions",{method:"POST",body:JSON.stringify({tenantId:"drawbridge-demo-browser",sessionId:stored.identity,resumeToken:stored.resumeToken})});
  if(resumed.status<200||resumed.status>=300||!resumed.body?.ok){
    setFailure(resumed.body,{capability:isCapabilityFailure(resumed.status,resumed.body),blockJourney:true});
    return false;
  }
  bindSession(stored.identity,resumed.body);
  const status=await authorizedJson("/api/sessions/"+sessionRef);
  if(status.status<200||status.status>=300||!status.body?.ok){
    setFailure(status.body,{capability:isCapabilityFailure(status.status,status.body),blockJourney:true});
    return false;
  }
  const pendingRequestId=projectStatus(status.body);
  if(pendingRequestId){
    pollAttempts=0;
    schedulePoll(pendingRequestId,0);
  }else submit.disabled=false;
  return true;
}
async function ensureSession(){
  if(sessionRef&&sessionCapability)return sessionRef;
  if(capabilityBlocked)throw new Error("session_recovery_action_required");
  const identity=crypto.randomUUID();
  const {body}=await json("/api/sessions",{method:"POST",body:JSON.stringify({tenantId:"drawbridge-demo-browser",sessionId:identity})});
  if(!body.ok)throw new Error((body.holds||["session_start_failed"]).join(", "));
  bindSession(identity,body);
  return sessionRef;
}
function schedulePoll(requestId,delay){
  cancelPoll();
  activePendingRequestId=requestId;
  submit.disabled=true;
  retryPending.hidden=true;
  pollTimer=setTimeout(()=>{pollTimer=null;void poll(requestId);},delay);
}
async function fetchSessionStatus(){
  const status=await authorizedJson("/api/sessions/"+sessionRef);
  if(isCapabilityFailure(status.status,status.body)){
    setFailure(status.body,{capability:true});
    return null;
  }
  if(status.status<200||status.status>=300||!status.body?.ok)throw new Error(failureText(status.body));
  return status.body;
}
async function reconcilePending(requestId,outcome){
  const statusBody=await fetchSessionStatus();
  if(!statusBody)return;
  const nextPendingRequestId=projectStatus(statusBody);
  if(nextPendingRequestId){
    if(nextPendingRequestId!==requestId)pollAttempts=0;
    schedulePoll(nextPendingRequestId,900);
    return;
  }
  if(outcome?.ok&&typeof outcome.response==="string"){
    state.textContent="OBSERVED";
    requestRef.textContent=requestId;
    response.textContent=outcome.response;
    assessment.textContent=outcome.assessment?.status||"Not observed";
    reason.textContent=outcome.assessment?.reason||"No reason supplied";
    receipt.textContent=outcome.receiptReference||"None";
    projectAttestation(outcome.attestationReference);
  }else if(outcome&&!outcome.ok){
    state.textContent="RETIRED";
    requestRef.textContent=requestId;
    assessment.textContent="Not observed";
    reason.textContent=failureText(outcome);
    receipt.textContent="None";
    projectAttestation(null);
    response.textContent="Durable status confirms that this pending request no longer blocks the session.";
  }
  submit.disabled=false;
}
async function poll(requestId){
  if(pageClosed)return;
  if(activePendingRequestId&&activePendingRequestId!==requestId)return;
  activePendingRequestId=requestId;
  submit.disabled=true;
  retryPending.hidden=true;
  if(++pollAttempts>MAX_POLL_ATTEMPTS){setPendingFailure(requestId,{holds:["agent_response_poll_ceiling_reached"]});return;}
  try{
    const result=await authorizedJson("/api/turns/"+requestId+"/complete",{method:"POST",body:"{}"});
    if(isCapabilityFailure(result.status,result.body)){setFailure(result.body,{capability:true});return;}
    if(result.status===202){
      state.textContent="PENDING_AGENT_RESPONSE";
      schedulePoll(requestId,900);
      return;
    }
    await reconcilePending(requestId,result.body);
  }catch(error){setPendingFailure(requestId,{errors:[errorText(error)]});}
}
let initialization;
submit.addEventListener("click",async()=>{
  await initialization;
  if(capabilityBlocked||activePendingRequestId)return;
  cancelPoll();
  const value=prompt.value.trim();
  if(!value||!scenario.value){reason.textContent="Prompt and registered scenario are required.";return;}
  pollAttempts=0;submit.disabled=true;state.textContent="OPENING";response.textContent="Writing a bounded external-agent request…";
  requestRef.textContent="None";assessment.textContent="Not observed";reason.textContent="Awaiting a bounded request identifier.";
  receipt.textContent="None";projectAttestation(null);
  try{
    const activeSession=await ensureSession();
    const result=await authorizedJson("/api/prompts",{method:"POST",body:JSON.stringify({sessionRef:activeSession,prompt:value,scenarioId:scenario.value})});
    if(isCapabilityFailure(result.status,result.body)){setFailure(result.body,{capability:true});return;}
    if(hasHold(result.body,"session_pending_turn_requires_recovery")){
      const statusBody=await fetchSessionStatus();
      if(!statusBody)return;
      const recoveredRequestId=projectStatus(statusBody);
      if(!recoveredRequestId){setFailure(result.body,{blockJourney:true});return;}
      pollAttempts=0;
      schedulePoll(recoveredRequestId,0);
      return;
    }
    if(!result.body?.ok){setFailure(result.body);return;}
    if(!CAPABILITY.test(result.body.requestId||"")){setFailure({holds:["prompt_response_contract_invalid"]},{blockJourney:true});return;}
    activePendingRequestId=result.body.requestId;
    state.textContent="PENDING_AGENT_RESPONSE";
    requestRef.textContent=result.body.requestId;
    response.textContent="Waiting for the ChatGPT agent stand-in to return the exact request response.";
    reason.textContent=syntheticDemoOnly?"Synthetic demo evidence; no enforcement authority.":"Evidence disclosure missing";
    await poll(result.body.requestId);
  }catch(error){
    if(activePendingRequestId)setPendingFailure(activePendingRequestId,{errors:[errorText(error)]});
    else setFailure({errors:[errorText(error)]});
  }
});
retryPending.addEventListener("click",async()=>{
  await initialization;
  if(capabilityBlocked||pageClosed||!activePendingRequestId)return;
  const requestId=activePendingRequestId;
  pollAttempts=0;
  retryPending.hidden=true;
  submit.disabled=true;
  state.textContent="RETRYING_PENDING";
  response.textContent="Retrying the retained durable request; no new crossing was opened.";
  await poll(requestId);
});
newSession.addEventListener("click",()=>{
  cancelPoll();clearStoredSession();capabilityBlocked=false;newSession.hidden=true;eraseSession.hidden=true;
  state.textContent="IDLE";requestRef.textContent="None";assessment.textContent="Not observed";
  reason.textContent="New local session requested by the operator.";receipt.textContent="None";projectAttestation(null);
  response.textContent="Waiting for a crossing.";submit.disabled=false;
});
eraseSession.addEventListener("click",async()=>{
  if(!sessionRef||!sessionCapability)return;
  submit.disabled=true;
  try{
    const result=await authorizedJson("/api/sessions/"+sessionRef,{method:"DELETE"});
    if(isCapabilityFailure(result.status,result.body)){setFailure(result.body,{capability:true});return;}
    if(!result.body?.ok){
      if(activePendingRequestId)setPendingFailure(activePendingRequestId,result.body);
      else setFailure(result.body);
      return;
    }
    clearStoredSession();eraseSession.hidden=true;state.textContent="ERASED";requestRef.textContent="None";
    assessment.textContent="Not observed";reason.textContent="Local session and bounded raw exchange erased.";
    receipt.textContent="None";projectAttestation(null);response.textContent="Session erased. Start another crossing when ready.";
    submit.disabled=false;
  }catch(error){
    if(activePendingRequestId)setPendingFailure(activePendingRequestId,{errors:[errorText(error)]});
    else setFailure({errors:[errorText(error)]});
  }
});
window.addEventListener("pagehide",()=>{
  pageClosed=true;cancelPoll();
  for(const controller of inflightRequests)controller.abort(new Error("browser_page_closed"));
  inflightRequests.clear();
});
async function initialize(){
  submit.disabled=true;
  resumeWasRequested=hasStoredSessionEvidence();
  try{
    await loadRegions();
    const resumed=await resumeStoredSession();
    if(!resumed&&!capabilityBlocked){state.textContent="IDLE";submit.disabled=false;}
  }catch(error){setFailure({errors:[errorText(error)]},{blockJourney:resumeWasRequested});}
}
initialization=initialize();`;
}
