const screen='/continuation/approve';
const script=screen+'/browser.js';
const policy="default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'";

/** Staging fixture only; pass the separately bundled browser source, never a
 * request-selected path or asset. The deployed Worker does not import this. */
export function continuationApprovalPage(authOrigin:string,browserBundle:string){
 const origin=new URL(authOrigin);
 if(origin.protocol!=='https:'||origin.origin!==authOrigin||!browserBundle||browserBundle.length>100_000)throw new Error('invalid_auth_page');
 const page='<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>继续原设备登记</title><script type="module" src="'+script+'"></script></head><body><main>'+
 '<h1>继续原设备登记</h1><p>仅用于隔离验收。请选择本地生成的续接请求，不要上传账号密码或密钥文件。</p>'+
 '<label for="stage">续接请求（JSON）</label><input id="stage" type="file" accept=".json,application/json"><button id="review" type="button">查看待确认操作</button>'+
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
 * surfaces on the same independent origin. Manual JSON is not a customer flow:
 * production needs an opaque short-lived handoff opened from the original CLI,
 * with artifacts in protected state and no credentials in the URL. */
export function continuationApprovalSurface(authOrigin:string,browserBundle:string,
 approve:(request:Request)=>Promise<Response>,readback:(request:Request)=>Promise<Response>){
 const assets=continuationApprovalPage(authOrigin,browserBundle);
 return (request:Request)=>{
  const u=new URL(request.url);
  if(u.origin===authOrigin&&!u.search){
   if(u.pathname==='/v1/auth/continuation-approval/begin'||u.pathname==='/v1/auth/continuation-approval/complete')return approve(request);
   if(u.pathname==='/v1/auth/continuation-receipt')return readback(request);
  }
  return assets(request);
 };
}
