import {readFileSync,mkdirSync,writeFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {resolve,dirname} from 'node:path';
import {createHash} from 'node:crypto';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
export const plan=JSON.parse(readFileSync(resolve(root,'provisioning/plan.json'),'utf8'));
const service=(binding,worker,entrypoint)=>({binding,service:plan.workers[worker],entrypoint});
export function manifests(input){
 const {main,custodian,auth,webDomain=plan.webDomain,apiDomain=plan.apiDomain,emailFrom}=input;
 const ids=[main,custodian,auth];if(ids.some(id=>typeof id!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(id))||new Set(ids).size!==3)throw new Error('invalid_resource_ids');
 for(const domain of [webDomain,apiDomain])if(typeof domain!=='string'||!/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(domain)||/example|invalid|localhost/.test(domain))throw new Error('invalid_domain');
 if(apiDomain===webDomain||!apiDomain.endsWith('.'+webDomain)||!emailFrom||!/^[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+$/.test(emailFrom))throw new Error('invalid_ingress');
 const db=(binding,name,id,folder)=>({binding,database_name:plan.databases[name],database_id:id,migrations_dir:`../../${folder}/migrations`});
 const a=w=>service('RECOVERY_AUTH',w,'RecoveryAuthority'),k=w=>service('RECOVERY_KEYS',w,'RecoveryKeys'),r=w=>service('RECOVERY_RELEASE_SIGNER',w,'RecoveryReleaseSigner');
 return Object.fromEntries(Object.entries(plan.workers).map(([folder,name])=>{
  const config={name,main:`../../${folder}/index.ts`,compatibility_date:plan.compatibilityDate,compatibility_flags:plan.compatibilityFlags,workers_dev:false,preview_urls:false,observability:{enabled:false}};
  if(folder==='api-worker')Object.assign(config,{routes:[webDomain,apiDomain].map(pattern=>({pattern,custom_domain:true})),d1_databases:[db('MAIN','main',main,'api-worker')],services:[service('RECOVERY','recovery-worker','Custodian'),service('EMAIL_VERIFIER','auth-trust-worker','EmailVerifier'),service('TRUSTED_AUTH_SOURCE','auth-trust-worker','TrustedAuthSource'),service('CHECKPOINT_SIGNER','api-trust-worker','CheckpointSigner'),a('api-trust-worker'),k('api-trust-worker'),r('api-trust-worker'),service('RECOVERY_ACCOUNT_ATTESTER','api-trust-worker','AccountAttester')],vars:{AUTH_ORIGIN:'https://'+webDomain,AUTH_RP_ID:webDomain},assets:{directory:'../../web/dist',binding:'ASSETS',run_worker_first:true,not_found_handling:'single-page-application'}});
  if(folder==='recovery-worker')Object.assign(config,{d1_databases:[db('CUSTODIAN','custodian',custodian,'recovery-worker')],services:[a('custody-trust-worker'),k('custody-trust-worker'),r('custody-trust-worker'),service('ROSTER_WITNESS_SIGNER','custody-trust-worker','RosterWitnessSigner'),service('RECOVERY_TRUST_SIGNER','custody-trust-worker','RecoveryTrustSigner'),service('RECOVERY_TRUST_POLICY','custody-trust-worker','RecoveryTrustPolicy')]});
  if(folder==='auth-trust-worker')Object.assign(config,{d1_databases:[db('AUTH','auth',auth,'auth-trust-worker')],send_email:[{name:'EMAIL'}],triggers:{crons:['17 * * * *']},vars:{EMAIL_FROM:emailFrom}});
  if(folder==='api-trust-worker')Object.assign(config,{d1_databases:[db('TRUST_DB','main',main,'api-worker')]});
  if(folder==='custody-trust-worker')Object.assign(config,{d1_databases:[db('TRUST_DB','custodian',custodian,'recovery-worker')]});
  validate(config);return [folder,config];
 }));
}
export function validate(config){
 if(!Object.values(plan.workers).includes(config.name)||config.workers_dev!==false||config.preview_urls!==false||config.compatibility_date!==plan.compatibilityDate||JSON.stringify(config.compatibility_flags)!==JSON.stringify(['nodejs_compat']))throw new Error('invalid_worker_plan');
 if(config.name!==plan.workers['api-worker']&&config.routes?.length)throw new Error('private_worker_route');
 for(const s of config.services??[])if(!Object.values(plan.workers).includes(s.service)||!s.entrypoint)throw new Error('invalid_service');
 if(/PLACEHOLDER|REPLACE_ME|\$\{|00000000-0000/.test(JSON.stringify(config)))throw new Error('unresolved_placeholder');
}
export function validateReleaseOwnership(release,peer){
 if(!Array.isArray(peer?.api)||!Array.isArray(peer?.custodian)||!peer.api.length||!peer.custodian.length||peer.api.length>64||peer.custodian.length>64)throw new Error('missing_operator_pins');
 const flat=[...peer.api,...peer.custodian];if(new Set(flat).size!==flat.length||flat.some(k=>typeof k!=='string'||Buffer.from(k,'base64').length!==32||Buffer.from(k,'base64').toString('base64')!==k))throw new Error('invalid_operator_pins');
 for(const p of [...release.checkpointKeys,release.recoveryServices.api])if(!peer.api.includes(p.publicKey))throw new Error('api_pin_mismatch');
 for(const p of [...release.witnessKeys,...release.recoveryAuthorities,release.recoveryServices.custodian])if(!peer.custodian.includes(p.publicKey))throw new Error('custody_pin_mismatch');
 return release;
}
export function releaseManifest(input,apiDomain,peer){
 const groups=['checkpointKeys','witnessKeys','recoveryAuthorities'];const all=[];
 for(const group of groups){if(!Array.isArray(input[group])||!input[group].length||input[group].length>16)throw new Error('missing_public_pins');all.push(...input[group]);}
 if(!input.recoveryServices?.api||!input.recoveryServices?.custodian)throw new Error('missing_public_pins');all.push(input.recoveryServices.api,input.recoveryServices.custodian);
 for(const pin of all){if(Object.keys(pin).sort().join(',')!=='keyId,publicKey'||typeof pin.publicKey!=='string'||Buffer.from(pin.publicKey,'base64').length!==32||Buffer.from(pin.publicKey,'base64').toString('base64')!==pin.publicKey||pin.keyId!==createHash('sha256').update(pin.publicKey).digest('hex'))throw new Error('invalid_public_pin');}
 if(new Set(all.map(p=>p.publicKey)).size!==all.length||typeof input.releaseId!=='string'||! /^[A-Za-z0-9_-]{1,128}$/.test(input.releaseId))throw new Error('invalid_release_pins');
 const release={witnessKeys:[...input.witnessKeys].sort((a,b)=>a.keyId.localeCompare(b.keyId)),recoveryServices:input.recoveryServices,recoveryAuthorities:[...input.recoveryAuthorities].sort((a,b)=>a.keyId.localeCompare(b.keyId)),version:1,releaseId:input.releaseId,apiOrigin:'https://'+apiDomain,protocolMin:2,protocolMax:2,checkpointKeys:[...input.checkpointKeys].sort((a,b)=>a.keyId.localeCompare(b.keyId))};
 return validateReleaseOwnership(release,peer);
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{
  const input={main:process.env.AKC_MAIN_D1_ID,custodian:process.env.AKC_CUSTODIAN_D1_ID,auth:process.env.AKC_AUTH_D1_ID,webDomain:process.env.AKC_WEB_DOMAIN??plan.webDomain,apiDomain:process.env.AKC_API_DOMAIN??plan.apiDomain,emailFrom:process.env.AKC_EMAIL_FROM};
  const configs=manifests(input);
  // Provisioning must supply actual public pins; no synthetic release fallback.
  const peer=JSON.parse(process.env.AKC_OPERATOR_PUBLIC_KEYS??'');
  const release=releaseManifest(JSON.parse(process.env.AKC_PUBLIC_PINS??''),input.apiDomain,peer);
  configs['api-trust-worker'].vars={PEER_PUBLIC_KEYS:JSON.stringify(peer.custodian)};
  configs['custody-trust-worker'].vars={PEER_PUBLIC_KEYS:JSON.stringify(peer.api),RELEASE_POLICY:JSON.stringify(release)};
  const output=resolve(root,'provisioning/generated');mkdirSync(output,{recursive:true,mode:0o700});
  for(const [folder,config] of Object.entries(configs))writeFileSync(resolve(output,folder+'.json'),JSON.stringify(config,null,2)+'\n',{mode:0o600});
  writeFileSync(resolve(output,'release-manifest.unsigned.json'),JSON.stringify(release)+'\n',{mode:0o600});
  console.log('Rendered five private-mode deployment configurations and an unsigned release candidate. No deployment performed.');
 }catch{console.error('Provisioning inputs invalid or incomplete; no deployment performed.');process.exitCode=1;}
}
