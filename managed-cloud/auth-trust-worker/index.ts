import {WorkerEntrypoint} from 'cloudflare:workers';
import {emailVerifier,sourceIdentity,cleanupAuth,type AuthConfig} from './service.ts';
interface Env extends Omit<AuthConfig,'EMAIL'> {EMAIL:SendEmail;EMAIL_FROM:string}
class Private extends WorkerEntrypoint<Env>{override async fetch(){return new Response(null,{status:404});}}
export class EmailVerifier extends Private {
 #service(){
  const env=this.env;
   if(!env.EMAIL||typeof env.EMAIL.send!=='function'||!env.EMAIL_FROM||! /^[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+$/.test(env.EMAIL_FROM))throw new Error('unavailable');
  return emailVerifier({...env,EMAIL:{async sendCode(recipient,code){
   await env.EMAIL.send({from:env.EMAIL_FROM,to:recipient,subject:'AgentKeychain verification code',text:`Your verification code is ${code}. It expires in 10 minutes. If you did not request this, ignore this message.`});
  }}});
 }
 async request(email:string,purpose:string,contextDigest:string){return this.#service().request(email,purpose,contextDigest);}
 async verify(email:string,proof:string){return this.#service().verify(email,proof);}
}
export class TrustedAuthSource extends Private {async resolve(request:Request){return sourceIdentity(request,this.env.SOURCE_HASH_KEY);}}
export default {fetch(){return new Response(null,{status:404});},scheduled(_controller:ScheduledController,env:Env,ctx:ExecutionContext){ctx.waitUntil(cleanupAuth(env.AUTH));}};
