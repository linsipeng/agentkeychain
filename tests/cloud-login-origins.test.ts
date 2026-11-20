import {expect,test} from 'bun:test';
import {authorizationBrowser} from '../src/cloud/login.ts';
import {testPolicy} from './cloud-http.test.ts';
test('login accepts signed Web entrypoints and rejects API or substituted browser/verification origins',async()=>{
 const {policy}=await testPolicy();
 const valid={browserUri:policy.webOrigin+'/app/devices/add?code=synthetic',verificationUri:policy.webOrigin+'/v1/auth/devices/verification'};
 expect(authorizationBrowser(policy,valid).origin).toBe(policy.webOrigin);
 for(const field of ['browserUri','verificationUri'] as const){
  for(const origin of [policy.apiOrigin,'https://attacker.invalid','https://local.invalid.attacker.invalid','https://user:pass@local.invalid'])expect(()=>authorizationBrowser(policy,{...valid,[field]:valid[field].replace(policy.webOrigin,origin)})).toThrow('cloud_invalid_authorization');
  for(const value of [undefined,'not a URL',valid[field]+'#fragment',policy.webOrigin+'/wrong'])expect(()=>authorizationBrowser(policy,{...valid,[field]:value} as typeof valid)).toThrow('cloud_invalid_authorization');
 }
});
test('environment overrides cannot redirect either signed role',async()=>{
 const {policy}=await testPolicy(),names=['AKC_CLOUD_ORIGIN','AKC_API_ORIGIN','AKC_WEB_ORIGIN','AKC_API_DOMAIN','AKC_WEB_DOMAIN','AUTH_ORIGIN','DEVICE_API_ORIGIN'],old=names.map(n=>process.env[n]);
 try{
  for(const n of names)process.env[n]='https://attacker.invalid';
  expect(policy.apiOrigin).toBe('https://api.local.invalid');
  expect(authorizationBrowser(policy,{browserUri:policy.webOrigin+'/app/devices/add?code=test',verificationUri:policy.webOrigin+'/v1/auth/devices/verification'}).origin).toBe('https://local.invalid');
 }finally{names.forEach((n,i)=>{if(old[i]===undefined)delete process.env[n];else process.env[n]=old[i];});}
});
