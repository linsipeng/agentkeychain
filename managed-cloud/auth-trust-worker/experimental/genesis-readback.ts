import {exactFields,type SignedManagedOperation} from '../../../src/cloud/protocol.ts';
import {boundedBody,digest} from '../../shared/contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from '../../shared/device-protocol.ts';
import {verifyGenesisApproval,type GenesisApprovalPolicy} from '../../shared/genesis-approval.ts';
import {rosterDigest} from '../../shared/roster.ts';

const path='/v1/auth/first-device-receipt';
const sessionCookie='__Host-akc_genesis_session';
const csrfCookie='__Host-akc_genesis_csrf';
const scrubbedHeaders={'cache-control':'no-store','pragma':'no-cache'};
const reject=()=>Response.json({error:{code:'genesis_receipt_unavailable'}},{status:401,headers:scrubbedHeaders});
function readCookie(headers:Headers,name:string){
 const pairs=(headers.get('cookie')??'').split(';').map(v=>v.trim()).filter(v=>v.startsWith(name+'='));
 if(pairs.length!==1)throw new Error('invalid');
 const value=pairs[0]!.slice(name.length+1);
 if(!/^[A-Za-z0-9_-]{43}$/.test(value))throw new Error('invalid');
 return value;
}
/** Only Auth's own authenticated approval UI may originate this exact intent. */
export const genesisReadbackIntent=(decisionId:string,grantDigest:string,signedRosterDigest:string)=>
 digest(JSON.stringify(['AgentKeychain-genesis-receipt-readback-v1',decisionId,grantDigest,signedRosterDigest]));

/** Unwired, proof-only Auth handler. Never deploy without an independently
 * owned Auth session/role lifecycle and exact approval-to-readback issuance. */
export function genesisReadback(db:D1Database,origin:string,policy:GenesisApprovalPolicy) {
 const configured=new URL(origin);
 if(configured.protocol!=='https:'||configured.origin!==origin)throw new Error('invalid_auth_origin');
 return async (req:Request)=>{
  try{
   const url=new URL(req.url);
   if(url.origin!==origin||url.pathname!==path||url.search||req.method!=='POST'||req.headers.get('origin')!==origin||
     req.headers.get('sec-fetch-site')==='cross-site'||!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(req.headers.get('content-type')??''))
    return reject();
   const sessionDigest=await digest(readCookie(req.headers,sessionCookie));
   const csrf=readCookie(req.headers,csrfCookie);
   if(req.headers.get('x-csrf-token')!==csrf)return reject();
   const csrfDigest=await digest(csrf);
   const input:unknown=JSON.parse(await boundedBody(req,24_576));
   exactFields(input,['decisionId','grant','roster']);
   const {decisionId,grant,roster}=input;
   if(typeof decisionId!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(decisionId)||
      typeof grant!=='string'||grant.length>4096)
    return reject();
   const g=JSON.parse(grant) as EnrollmentGrant;
   if(canonicalGrant(g)!==grant||g.issuerDeviceId!==null)return reject();
   exactFields(roster,['canonical','signature']);
   if(typeof roster.canonical!=='string'||roster.canonical.length>16_384||typeof roster.signature!=='string'||roster.signature.length>100)
    return reject();
   const signed=roster as unknown as SignedManagedOperation;
   const grantDigest=await digest(grant), signedRosterDigest=await rosterDigest(signed);
   const action=await genesisReadbackIntent(decisionId,grantDigest,signedRosterDigest);
   const read=()=>db.prepare(`SELECT d.canonical,d.signature
      FROM auth_genesis_decisions d JOIN auth_genesis_challenges c ON c.id=d.id AND c.grant_digest=d.grant_digest
      JOIN auth_genesis_pins p USING(account,tenant,vault,credential)
      JOIN auth_genesis_view_sessions s ON s.account=c.account AND s.tenant=c.tenant AND s.vault=c.vault
      JOIN auth_genesis_view_grants v ON v.session_digest=s.session_digest
      WHERE d.id=? AND d.grant_digest=? AND c.roster_digest=? AND c.expires>unixepoch()
      AND c.account=? AND c.tenant=? AND c.vault=? AND p.active=1
      AND s.session_digest=? AND s.csrf_digest=? AND s.approval_reader=1 AND s.revoked=0 AND s.expires>unixepoch()
      AND v.intent_digest=? AND v.issued<=unixepoch() AND v.expires>unixepoch()`)
    .bind(decisionId,grantDigest,signedRosterDigest,g.accountId,g.tenantId,g.vaultId,sessionDigest,csrfDigest,action)
    .first<{canonical:string;signature:string}>();
   const proof=await read();
   if(!proof)return reject();
   const verified=await verifyGenesisApproval(proof,grant,signed,policy);
   if(verified.decisionId!==decisionId)return reject();
   const current=await read();
   if(!current||current.canonical!==proof.canonical||current.signature!==proof.signature)return reject();
   return Response.json(proof,{headers:scrubbedHeaders});
  }catch{return reject();}
 };
}
