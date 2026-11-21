type ExactStage = {oldGrantCanonical:string;target:{canonical:string;signature:string};roster:unknown;keyPackage:unknown};
type Challenge = {id:string;options:{challenge:string;rpId:string;userVerification:string;allowCredentials:{id:string;type:PublicKeyCredentialType}[]};
 display:{purpose:string;deviceId:string;accountId:string;vaultId:string}};
const approval='/v1/auth/continuation-approval/', handoff='/v1/auth/continuation-handoff/';
const opaque=(v:unknown):v is string=>typeof v==='string'&&/^[A-Za-z0-9_-]{1,128}$/.test(v);
const bytes=(s:string)=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),x=>x.charCodeAt(0));
const encode=(a:ArrayBuffer)=>btoa(String.fromCharCode(...new Uint8Array(a))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
function csrf(name='__Host-akc_genesis_csrf'){
 const values=document.cookie.split(';').map(x=>x.trim()).filter(x=>x.startsWith(name+'='));
 const token=values[0]?.slice(name.length+1);
 if(values.length!==1||!opaque(token)||token.length!==43)throw new Error('missing_csrf');
 return token;
}
async function post<T>(path:string,body:unknown,withCsrf=false,csrfName?:string):Promise<T>{
 const result=await fetch(path,{method:'POST',headers:{'content-type':'application/json',...(withCsrf?{'x-csrf-token':csrf(csrfName)}: {})},
  credentials:'same-origin',cache:'no-store',redirect:'error',body:JSON.stringify(body)});
 if(!result.ok)throw new Error('approval_unavailable');
 return await result.json();
}
export function startContinuationApprovalPage(){
 const id=<T extends HTMLElement>(name:string)=>document.getElementById(name) as T;
 const pick=id<HTMLInputElement>('stage'),review=id<HTMLButtonElement>('review'),approve=id<HTMLButtonElement>('approve');
 const recover=id<HTMLButtonElement>('recover'),download=id<HTMLButtonElement>('download'),details=id<HTMLElement>('details');
 const code=id<HTMLInputElement>('pair-code');
 const locator=/^#handoff=([A-Za-z0-9_-]{43})$/.exec(location.hash)?.[1];
 if(locator){id('manual').hidden=true;id('handoff').hidden=false;}
 const status=(value:string)=>{id<HTMLElement>('status').textContent=value;};
 let pending:{proposal:ExactStage;challenge:Challenge}|null=null, saved:{canonical:string;signature:string}|null=null;
 let busy=false;
 function erase(){pending=null;saved=null;details.hidden=true;approve.disabled=true;recover.disabled=true;download.disabled=true;}
 function retain(value:{canonical:string;signature:string}){
  if(typeof value.canonical!=='string'||value.canonical.length>1024||typeof value.signature!=='string'||value.signature.length>100)throw new Error('invalid_receipt');
  saved={canonical:value.canonical,signature:value.signature};recover.disabled=true;download.disabled=false;
  status('已收到签名回执。请下载后交回原设备验证；此页面不代表设备已经激活。');
 }
 pick.addEventListener('change',()=>{erase();status('请选择要确认的续接请求。');});
 review.addEventListener('click',async()=>{
  if(busy)return;erase();
  const local=pick.files?.[0];
  if(!locator&&(!local||local.size>60_000)){status('请选择不超过 60 KB 的续接请求 JSON。');return;}
  const pairCode=code.value;
  if(locator&&!/^[0-9]{8}$/.test(pairCode)){status('请输入原设备显示的 8 位配对码。');return;}
  busy=true;review.disabled=true;pick.disabled=true;code.disabled=true;
  try{
   let proposal:ExactStage;
   if(locator){
    await post(handoff+'browser',{locator});
    proposal=(await post<{stage:ExactStage}>(handoff+'claim',{locator,pairCode},true,'__Host-akc_handoff_csrf')).stage;
    code.value='';
   }else proposal=JSON.parse(await local!.text()) as ExactStage;
   const challenge=await post<Challenge>(approval+'begin',{stage:proposal}),d=challenge.display;
   if(d.purpose!=='continue-original-device-key-package'||![d.deviceId,d.accountId,d.vaultId].every(opaque)||
      !opaque(challenge.id)||challenge.id.length!==43||challenge.options.userVerification!=='required'||challenge.options.rpId!==location.hostname)
    throw new Error('invalid_challenge');
   id<HTMLElement>('purpose').textContent='继续登记同一台设备：仅提交加密密钥包';
   id<HTMLElement>('device').textContent=d.deviceId;id<HTMLElement>('account').textContent=d.accountId;id<HTMLElement>('vault').textContent=d.vaultId;
   pending={proposal,challenge};details.hidden=false;approve.disabled=false;
   status('请核对设备和操作。确认后才会打开通行密钥验证。');
  }catch{status('无法准备审批。未提交批准。');}finally{busy=false;review.disabled=false;pick.disabled=false;code.disabled=false;}
 });
 approve.addEventListener('click',async()=>{
  if(busy||!pending||approve.disabled)return;
  const {proposal,challenge}=pending;
  busy=true;approve.disabled=true;review.disabled=true;pick.disabled=true;code.disabled=true;
  let sent=false;
  try{
   if(!window.isSecureContext||!window.PublicKeyCredential||!navigator.credentials)throw new Error('passkey_unavailable');
   const options=challenge.options;
   const assertion=await navigator.credentials.get({publicKey:{challenge:bytes(options.challenge),rpId:options.rpId,userVerification:'required',
    allowCredentials:options.allowCredentials.map(x=>({id:bytes(x.id),type:x.type}))}}) as PublicKeyCredential|null;
   if(!assertion)throw new Error('passkey_cancelled');
   const r=assertion.response as AuthenticatorAssertionResponse;
   const response={id:assertion.id,rawId:encode(assertion.rawId),type:'public-key',clientExtensionResults:assertion.getClientExtensionResults(),
    authenticatorAttachment:assertion.authenticatorAttachment??undefined,response:{clientDataJSON:encode(r.clientDataJSON),authenticatorData:encode(r.authenticatorData),
     signature:encode(r.signature),userHandle:r.userHandle?encode(r.userHandle):null}};
   sent=true;
   retain(await post(approval+'complete',{id:challenge.id,stage:proposal,assertion:response},true));
  }catch{
   if(sent){recover.disabled=false;status('无法确认提交结果。请查询已提交的审批，不要重复验证。');}
   else{approve.disabled=false;status('通行密钥验证未完成，未提交批准。');}
  }finally{busy=false;review.disabled=sent;pick.disabled=sent;code.disabled=sent;}
 });
 recover.addEventListener('click',async()=>{
  if(busy||!pending||recover.disabled)return;
  const {proposal,challenge}=pending;busy=true;recover.disabled=true;
  try{retain(await post('/v1/auth/continuation-receipt',{decisionId:challenge.id,oldGrantCanonical:proposal.oldGrantCanonical,target:proposal.target},true));}
  catch{recover.disabled=false;status('暂时没有已确认的回执。请稍后再查询。');}finally{busy=false;}
 });
 download.addEventListener('click',()=>{
  if(!saved)return;
  const address=URL.createObjectURL(new Blob([JSON.stringify(saved)],{type:'application/json'})),link=document.createElement('a');
  link.href=address;link.download='agentkeychain-continuation-receipt.json';link.click();URL.revokeObjectURL(address);
 });
}
if(typeof document!=='undefined'&&document.getElementById('stage'))startContinuationApprovalPage();
