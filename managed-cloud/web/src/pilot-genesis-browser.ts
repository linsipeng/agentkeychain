type Op={canonical:string;signature:string};
type Fixture={invite:Op;oldGrantCanonical:string;roster:Op};
type ExactDisplay={accountId:string;vaultId:string;deviceId:string};
type CredentialList={id:string;type:PublicKeyCredentialType;transports?:AuthenticatorTransport[]};
type Creation=Omit<PublicKeyCredentialCreationOptions,'challenge'|'user'|'excludeCredentials'>&{challenge:string;user:Omit<PublicKeyCredentialUserEntity,'id'>&{id:string};excludeCredentials?:CredentialList[]};
type Get=Omit<PublicKeyCredentialRequestOptions,'challenge'|'allowCredentials'>&{challenge:string;allowCredentials?:CredentialList[]};
const path='/v1/auth/pilot-genesis/';
const opaque=(v:unknown):v is string=>typeof v==='string'&&/^[A-Za-z0-9_-]{43}$/.test(v);
const bytes=(s:string)=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),x=>x.charCodeAt(0));
const encode=(value:ArrayBuffer)=>btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const validId=(value:unknown):value is string=>typeof value==='string'&&/^[A-Za-z0-9_-]{1,128}$/.test(value);
const operation=(v:unknown):v is Op=>!!v&&typeof v==='object'&&Object.keys(v).length===2&&'canonical' in v&&'signature' in v&&
 typeof v.canonical==='string'&&typeof v.signature==='string'&&v.signature.length<=100;
const ensure=(v:unknown):void=>{if(!v)throw new Error('pilot_scope_invalid');};

async function post<T>(subpath:string,body:Fixture&Record<string,unknown>,csrf?:string):Promise<T>{
 const r=await fetch(path+subpath,{method:'POST',credentials:'same-origin',redirect:'error',cache:'no-store',referrerPolicy:'no-referrer',
  headers:{'content-type':'application/json',...(csrf?{'x-csrf-token':csrf}:{})},body:JSON.stringify(body)});
 if(!r.ok)throw new Error('pilot_operation_unavailable');
 return (r.status===204?undefined:await r.json()) as T;
}
export function startPilotGenesisBrowser(){
 const find=<T extends HTMLElement>(label:string)=>document.getElementById(label) as T;
 const fixture=find<HTMLInputElement>('fixture'),register=find<HTMLButtonElement>('register'),review=find<HTMLButtonElement>('review-approval'),
  approve=find<HTMLButtonElement>('approve'),readback=find<HTMLButtonElement>('readback');
 const status=(value:string)=>{find('status').textContent=value;};
 let proposal:Fixture|null=null,display:ExactDisplay|null=null,csrf:string|undefined,id:string|undefined,challenge:Get|undefined;
 let busy=false;
 function run(callback:()=>Promise<void>){
  if(busy)return;
  busy=true;
  void callback().catch(()=>status('操作未完成。没有确认设备激活。')).finally(()=>{busy=false;});
 }
 fixture.addEventListener('change',()=>run(async()=>{
  proposal=null;display=null;register.disabled=true;find('details').hidden=true;
  const file=fixture.files?.[0];fixture.value='';
  if(!file||file.size>48_000)throw new Error('invalid_fixture');
  const data:Fixture=JSON.parse(await file.text());
  ensure(Object.keys(data).length===3&&operation(data.invite)&&operation(data.roster)&&typeof data.oldGrantCanonical==='string'&&data.oldGrantCanonical.length<=4096);
  const grant:ExactDisplay=JSON.parse(data.oldGrantCanonical);
  ensure(validId(grant.accountId)&&validId(grant.vaultId)&&validId(grant.deviceId));
  display={accountId:grant.accountId,vaultId:grant.vaultId,deviceId:grant.deviceId};
  for(const [field,label] of [['accountId','account'],['vaultId','vault'],['deviceId','device']] as const)find(label).textContent=display[field];
  proposal=data;find('details').hidden=false;register.disabled=false;
  status('请先核对测试设备，再注册此来源的通行密钥。注册不会批准设备。');
 }));
 register.addEventListener('click',()=>run(async()=>{
  if(!proposal||register.disabled||!isSecureContext||!window.PublicKeyCredential)throw new Error('registration_unavailable');
  register.disabled=true;fixture.disabled=true;
  const begun=await post<{options:Creation;csrf:string}>('registration/begin',proposal);
  const {options}=begun;
  ensure(opaque(begun.csrf)&&options.rp.id===location.hostname&&options.authenticatorSelection?.userVerification==='required');
  csrf=begun.csrf;
  const credential=await navigator.credentials.create({publicKey:{...options,challenge:bytes(options.challenge),
   user:{...options.user,id:bytes(options.user.id)},excludeCredentials:options.excludeCredentials?.map(d=>({...d,id:bytes(d.id)}))}}) as PublicKeyCredential|null;
  if(!credential)throw new Error('registration_cancelled');
  const response=credential.response as AuthenticatorAttestationResponse;
  await post('registration/complete',{...proposal,response:{id:credential.id,rawId:encode(credential.rawId),type:credential.type,
   clientExtensionResults:credential.getClientExtensionResults(),response:{clientDataJSON:encode(response.clientDataJSON),
    attestationObject:encode(response.attestationObject),transports:response.getTransports?.()}}},csrf);
  review.disabled=false;
  status('通行密钥已注册。请单独查看首台设备审批。');
 }));
 review.addEventListener('click',()=>run(async()=>{
  if(!proposal||!display||!csrf||review.disabled)throw new Error('consent_unavailable');
  const result=await post<{id:string;options:Get;display:ExactDisplay&{purpose:string}}>('consent/begin',proposal,csrf);
  ensure(opaque(result.id)&&result.options.rpId===location.hostname&&result.options.userVerification==='required'&&
   result.display.purpose==='approve-first-device-genesis'&&result.display.accountId===display.accountId&&
   result.display.deviceId===display.deviceId&&result.display.vaultId===display.vaultId);
  id=result.id;challenge=result.options;review.disabled=true;approve.disabled=false;
  status('请核对上面这台设备。只有点击批准，才会发起一次新的通行密钥验证。');
 }));
 function retain(value:Op){
  ensure(operation(value));
  find<HTMLTextAreaElement>('proof').value=JSON.stringify(value);find('receipt').hidden=false;
  readback.disabled=true;approve.disabled=true;proposal=null;csrf=undefined;id=undefined;challenge=undefined;
  status('已取得首台设备签名回执。这不表示设备已激活。');
 }
 approve.addEventListener('click',()=>run(async()=>{
  if(!proposal||!csrf||!id||!challenge||approve.disabled||!isSecureContext||!window.PublicKeyCredential)throw new Error('consent_unavailable');
  approve.disabled=true;
  let sent=false;
  try{
   const credential=await navigator.credentials.get({publicKey:{...challenge,challenge:bytes(challenge.challenge),userVerification:'required',
    allowCredentials:challenge.allowCredentials?.map(d=>({...d,id:bytes(d.id)}))}}) as PublicKeyCredential|null;
   if(!credential)throw new Error('approval_cancelled');
   const r=credential.response as AuthenticatorAssertionResponse;
   const response={id:credential.id,rawId:encode(credential.rawId),type:credential.type,clientExtensionResults:credential.getClientExtensionResults(),
    response:{clientDataJSON:encode(r.clientDataJSON),authenticatorData:encode(r.authenticatorData),signature:encode(r.signature),userHandle:r.userHandle?encode(r.userHandle):null}};
   sent=true;
   retain(await post<Op>('consent/complete',{...proposal,id,response},csrf));
  }catch{
   if(sent){readback.disabled=false;status('提交结果不明。请查询已提交的审批，不要重新批准。');}
   else {approve.disabled=false;status('通行密钥验证未完成，未提交批准。');}
  }
 }));
 readback.addEventListener('click',()=>run(async()=>{
  if(!proposal||!csrf||!id||readback.disabled)throw new Error('readback_unavailable');
  retain(await post<Op>('consent/readback',{...proposal,id},csrf));
 }));
}
if(typeof document!=='undefined'&&document.getElementById('fixture'))startPilotGenesisBrowser();
