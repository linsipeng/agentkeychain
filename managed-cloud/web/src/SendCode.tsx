import {useEffect,useState} from 'react';
import {api} from './api';
export function SendCode({email,purpose,context,copy}:{email:string;purpose:'invitation'|'recovery';context:string;copy:{send:string;sent:string;error:string;waiting:string}}){
 const [busy,setBusy]=useState(false),[until,setUntil]=useState(0),[now,setNow]=useState(0),[status,setStatus]=useState<'sent'|'error'|null>(null);
 useEffect(()=>{if(!until)return;const timer=setInterval(()=>setNow(Date.now()),250);return()=>clearInterval(timer);},[until]);
 const remaining=Math.max(0,Math.ceil((until-now)/1000));
 async function send(){setBusy(true);setStatus(null);try{await api('bootstrap');const r=await api<{accepted:boolean;retryAfter:number}>('email/request',{email,purpose,context});if(r.accepted!==true||r.retryAfter!==60)throw new Error('unavailable');const received=Date.now();setNow(received);setUntil(received+r.retryAfter*1000);setStatus('sent');}catch{setStatus('error');}finally{setBusy(false);}}
 return <><button type="button" disabled={busy||remaining>0||!email||!context} onClick={()=>void send()}>{busy?copy.waiting:remaining?`${copy.send} (${remaining})`:copy.send}</button>{status&&<p role="status" aria-live="polite">{copy[status]}</p>}</>;
}
