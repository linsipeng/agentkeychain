const screen='/continuation/approve';
const script=screen+'/browser.js';
const policy="default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'";

/** Staging fixture only; pass the separately bundled browser source, never a
 * request-selected path or asset. The deployed Worker does not import this. */
export function continuationApprovalPage(authOrigin:string,browserBundle:string){
 const origin=new URL(authOrigin);
 if(origin.protocol!=='https:'||origin.origin!==authOrigin||!browserBundle||browserBundle.length>100_000)throw new Error('invalid_auth_page');
 const page='<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>继续原设备登记</title><script type="module" src="'+script+'"></script></head><body><main>'+
 '<h1>继续原设备登记</h1><p>仅用于隔离验收。不需要输入账号密码或密钥。</p>'+
 '<div id="manual"><p>旧的隔离验收方式：选择本地生成的续接请求。</p><label for="stage">续接请求（JSON）</label><input id="stage" type="file" accept=".json,application/json"></div>'+
 '<div id="handoff" hidden><p>无需上传文件。请核对原设备上的配对码。</p><label for="pair-code">原设备显示的 8 位配对码</label><input id="pair-code" inputmode="numeric" autocomplete="one-time-code" maxlength="8"></div><button id="review" type="button">查看待确认操作</button>'+
 '<dl id="details" hidden><dt>操作</dt><dd id="purpose"></dd><dt>设备 ID</dt><dd id="device"></dd><dt>账号 ID</dt><dd id="account"></dd><dt>凭证库 ID</dt><dd id="vault"></dd></dl>'+
 '<button id="approve" type="button" disabled>使用通行密钥确认</button><button id="recover" type="button" disabled>查询已提交的审批</button>'+
 '<button id="download" type="button" disabled>下载签名回执</button><p id="status" role="status" aria-live="polite"></p></main></body></html>';
 return (request:Request)=>{
  const u=new URL(request.url);
  if(u.origin!==authOrigin||u.search||request.method!=='GET'||(u.pathname!==screen&&u.pathname!==script))return new Response(null,{status:404,headers:{'cache-control':'no-store'}});
  return new Response(u.pathname===screen?page:browserBundle,{headers:{
   'content-type':u.pathname===screen?'text/html; charset=utf-8':'application/javascript; charset=utf-8',
   'cache-control':'no-store','content-security-policy':policy,'x-content-type-options':'nosniff','x-frame-options':'DENY',
   'referrer-policy':'no-referrer','cross-origin-resource-policy':'same-origin','permissions-policy':'publickey-credentials-get=(self), publickey-credentials-create=()',
  }});
 };
}

/** Synthetic runtime composition only. The local fixture must mount all three
 * surfaces on the same independent origin. The optional handoff fixture accepts
 * a routing locator only in the page URL and a separately entered code. */
export function continuationApprovalSurface(authOrigin:string,browserBundle:string,
 approve:(request:Request)=>Promise<Response>,readback:(request:Request)=>Promise<Response>,handoff?:(request:Request)=>Promise<Response>,devicePoll?:(request:Request)=>Promise<Response>){
 const assets=continuationApprovalPage(authOrigin,browserBundle);
 return (request:Request)=>{
  const u=new URL(request.url);
  if(u.origin===authOrigin&&!u.search){
   if(u.pathname==='/v1/auth/continuation-approval/begin'||u.pathname==='/v1/auth/continuation-approval/complete')return approve(request);
   if(u.pathname==='/v1/auth/continuation-receipt')return readback(request);
   if(devicePoll&&u.pathname==='/v1/auth/continuation-handoff/poll')return devicePoll(request);
   if(handoff&&u.pathname.startsWith('/v1/auth/continuation-handoff/'))return handoff(request);
  }
  return assets(request);
 };
}
