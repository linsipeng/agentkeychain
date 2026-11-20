/** Signed ingress roles; never infer Web from API or accept environment overrides. */
export function validateReleaseOrigins(apiOrigin, webOrigin) {
 const parse=value=>{
  if(typeof value!=='string')throw new Error('invalid_release_origins');
  const url=new URL(value);
  if(url.protocol!=='https:'||url.origin!==value||url.username||url.password||url.pathname!=='/'||url.search||url.hash)throw new Error('invalid_release_origins');
  return url;
 };
 const api=parse(apiOrigin),web=parse(webOrigin);
 if(apiOrigin===webOrigin||api.hostname.length<=web.hostname.length+1||api.hostname.split('.').some(label=>!label)||web.hostname.split('.').some(label=>!label)||!api.hostname.endsWith('.'+web.hostname))throw new Error('invalid_release_origins');
}
