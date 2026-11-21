/** Child-process-only Chrome DevTools pipe. Never listens on TCP. */
export function chromiumTestPipe(child){
 const pending=new Map();
 let lastId=0,buffer='';
 const finish=error=>{
  for(const {reject} of pending.values())reject(error);
  pending.clear();
 };
 child.stdio[3].on('error',finish);
 child.stdio[4].on('error',finish);
 child.once('close',()=>finish(new Error('browser_pipe_closed')));
 child.stdio[4].setEncoding('utf8').on('data',chunk=>{
  buffer+=chunk;
  if(buffer.length>1024*1024){finish(new Error('browser_pipe_oversize'));return;}
  let end;
  while((end=buffer.indexOf('\0'))!==-1){
   const line=buffer.slice(0,end);buffer=buffer.slice(end+1);
   try{
    const msg=JSON.parse(line),entry=pending.get(msg.id);
    if(!entry)continue;
    pending.delete(msg.id);
    if(msg.error)entry.reject(new Error(entry.method+': '+msg.error.message));
    else entry.resolve(msg.result);
   }catch{finish(new Error('browser_pipe_invalid'));}
  }
 });
 return (method,params={},sessionId)=>new Promise((resolve,reject)=>{
  const id=++lastId;
  pending.set(id,{resolve,reject,method});
  child.stdio[3].write(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})})+'\0');
 });
}
