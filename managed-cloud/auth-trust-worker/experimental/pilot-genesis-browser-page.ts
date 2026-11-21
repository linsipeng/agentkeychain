export const PILOT_GENESIS_PAGE='/pilot/genesis';
const script=PILOT_GENESIS_PAGE+'/browser.js';
const csp="default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'";
/** Pilot-only page: local fixture input, no URL handoff or persistent browser state. */
export function pilotGenesisBrowserPage(origin:string,bundle:string,req:Request){
 const u=new URL(req.url);
 if(u.origin!==origin||u.search||req.method!=='GET'||(u.pathname!==PILOT_GENESIS_PAGE&&u.pathname!==script)||
    !bundle||bundle.length>100_000)return new Response(null,{status:404,headers:{'cache-control':'no-store'}});
 const page='<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'+
 '<title>首台设备隔离验收</title><script type="module" src="'+script+'"></script></head><body><main><h1>首台设备隔离验收</h1>'+
 '<p>仅用于一次性测试账号，不可提交真实账号、设备或凭证库。</p><label for="fixture">已签名的测试邀请文件</label>'+
 '<input type="file" id="fixture" accept=".json,application/json"><dl id="details" hidden><dt>测试账号</dt><dd id="account"></dd>'+
 '<dt>凭证库</dt><dd id="vault"></dd><dt>设备</dt><dd id="device"></dd></dl>'+
 '<button type="button" id="register" disabled>注册此来源的通行密钥</button>'+
 '<button type="button" id="review-approval" disabled>查看首台设备审批</button>'+
 '<button type="button" id="approve" disabled>仅批准上面这台设备</button>'+
 '<button type="button" id="readback" disabled>查回已提交的审批</button>'+
 '<p id="status" role="status" aria-live="polite"></p><div id="receipt" hidden><label for="proof">原始签名回执（设备未激活）</label>'+
 '<textarea id="proof" readonly autocomplete="off"></textarea></div></main></body></html>';
 return new Response(u.pathname===script?bundle:page,{headers:{
  'content-type':u.pathname===script?'application/javascript; charset=utf-8':'text/html; charset=utf-8',
  'cache-control':'no-store','content-security-policy':csp,'x-content-type-options':'nosniff','x-frame-options':'DENY',
  'referrer-policy':'no-referrer','cross-origin-resource-policy':'same-origin',
  'permissions-policy':'publickey-credentials-get=(self), publickey-credentials-create=(self)',
 }});
}
