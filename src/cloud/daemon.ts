import {randomUUID} from 'node:crypto';
/* global AbortSignal */
import {createServer,createConnection} from 'node:net';
import {chmodSync,lstatSync,unlinkSync} from 'node:fs';
import {join} from 'node:path';
import {retryDelay,CloudHttpError} from './http.ts';
import {secureNamespace} from '../platform/secure-store.ts';
import type {openCloudRuntime} from './runtime.ts';
const xml=(value:string)=>value.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&apos;');
const unit=(value:string)=>'"'+value.replaceAll('\\','\\\\').replaceAll('"','\\"').replaceAll('%','%%')+'"';
export function serviceArtifact(platform:'darwin'|'linux',binary:string,home:string){
 for(const value of [binary,home])if(!value.startsWith('/')||[...value].some(c=>c.charCodeAt(0)<32||c.charCodeAt(0)===127))throw new Error('invalid_service_path');
 if(platform==='darwin')return {name:'com.agentkeychain.cloud.plist',content:`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>Label</key><string>com.agentkeychain.cloud</string><key>ProgramArguments</key><array><string>${xml(binary)}</string><string>cloud</string><string>service</string><string>run</string></array><key>EnvironmentVariables</key><dict><key>AGENTKEYCHAIN_HOME</key><string>${xml(home)}</string></dict><key>RunAtLoad</key><true/><key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict><key>ThrottleInterval</key><integer>10</integer></dict></plist>\n`};
 return {name:'agentkeychain-cloud.service',content:`[Unit]\nDescription=AgentKeychain automatic updates\n[Service]\nType=simple\nExecStart=${unit(binary)} cloud service run\nEnvironment=${unit('AGENTKEYCHAIN_HOME='+home)}\nRestart=on-failure\nRestartSec=10\nUMask=0077\nNoNewPrivileges=true\n[Install]\nWantedBy=default.target\n`};
}
export async function wakeCloud(home:string,action:'wake'|'stop'='wake'):Promise<boolean>{
 secureNamespace(home);
 return new Promise(resolve=>{const socket=createConnection(join(home,'cloud.sock'));let settled=false;const finish=(ok:boolean)=>{if(!settled){settled=true;socket.destroy();resolve(ok);}};socket.setTimeout(1000,()=>finish(false));socket.on('connect',()=>socket.write(action+'\n'));socket.on('data',()=>finish(true));socket.on('error',()=>finish(false));socket.on('close',()=>finish(false));});
}
export async function runCloudDaemon(runtime:Awaited<ReturnType<typeof openCloudRuntime>>,home:string,signal:AbortSignal){
 secureNamespace(home);const path=join(home,'cloud.sock'),owner=randomUUID();
 if(await wakeCloud(home))throw new Error('cloud_service_already_running');
 let acquired=false,inode:number|undefined,renewal:ReturnType<typeof setInterval>|undefined;
 let wake:(()=>void)|undefined,stopping=false,lost=false;
 const abort=()=>wake?.();
 const server=createServer(socket=>{socket.setTimeout(1000,()=>socket.destroy());socket.once('data',bytes=>{if(bytes.length<=16&&['wake\n','stop\n'].includes(bytes.toString())){if(bytes.toString()==='stop\n')stopping=true;wake?.();socket.end('ok\n');}else socket.destroy();});socket.on('error',()=>{});});
 try{
  if(!runtime.store.acquireLease(owner,Date.now(),30000,2))throw new Error('cloud_service_already_running');acquired=true;
  if(await wakeCloud(home))throw new Error('cloud_service_already_running');
  try{const stat=lstatSync(path);if(!stat.isSocket())throw new Error('unsafe_cloud_socket');unlinkSync(path);}catch(error){if((error as {code?:string}).code!=='ENOENT')throw error;}
  await new Promise<void>((resolve,reject)=>{server.once('error',reject);server.listen(path,()=>{try{inode=lstatSync(path).ino;chmodSync(path,0o600);resolve();}catch(error){reject(error);}});});
  renewal=setInterval(()=>{if(!runtime.store.acquireLease(owner,Date.now(),30000,2)){lost=true;wake?.();}},10000);
  signal.addEventListener('abort',abort);let attempt=0;
  while(!signal.aborted&&!lost&&!stopping){
   let delay=30000;
   try{await runtime.engine.sync();attempt=0;}catch(error){const state=runtime.store.get<{state:string}>('state','health')?.state;if(state&&['revoked','security_error','auth_required','incompatible'].includes(state))break;delay=retryDelay(attempt++,error instanceof CloudHttpError?error.retryAfter:0);}
   if(signal.aborted||stopping||lost)break;
   await new Promise<void>(resolve=>{const timer=setTimeout(()=>{wake=undefined;resolve();},delay);wake=()=>{clearTimeout(timer);wake=undefined;resolve();};});
  }
 }finally{
  if(renewal)clearInterval(renewal);signal.removeEventListener('abort',abort);
  if(server.listening)await new Promise<void>(resolve=>server.close(()=>resolve()));
  try{if(inode!==undefined&&lstatSync(path).ino===inode)unlinkSync(path);}catch{/* already removed */}
  if(acquired)runtime.store.releaseLease(owner,2);
 }
}
/** Launch an already-installed compiled CLI without inheriting credential environment variables. */
export async function startCloudBackground(home:string){
 secureNamespace(home);if(await wakeCloud(home))return;
 const {spawn}=await import('node:child_process'),{homedir}=await import('node:os');
 const child=spawn(process.execPath,['cloud','service','run'],{detached:true,stdio:'ignore',env:{PATH:process.env.PATH??'/usr/bin:/bin',HOME:homedir(),AGENTKEYCHAIN_HOME:home,...(process.env.DBUS_SESSION_BUS_ADDRESS?{DBUS_SESSION_BUS_ADDRESS:process.env.DBUS_SESSION_BUS_ADDRESS}:{})}});
 await new Promise<void>((resolve,reject)=>{child.once('spawn',resolve);child.once('error',()=>reject(new Error('cloud_service_start_failed')));});child.unref();
}
