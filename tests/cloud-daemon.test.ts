import {expect,test} from 'bun:test';
import {serviceArtifact} from '../src/cloud/daemon.ts';
test('service artifacts contain only executable and metadata, escape paths, reject control characters',()=>{
 const mac=serviceArtifact('darwin','/tmp/a & b/client','/tmp/private');
 expect(mac.content).toContain('a &amp; b/client');expect(mac.content).toContain('<string>run</string>');expect(mac.content).not.toContain('AKC_PASSWORD');
 const linux=serviceArtifact('linux','/tmp/a%/client','/tmp/private');expect(linux.content).toContain('a%%/client');expect(linux.content).toContain('Restart=on-failure');
 expect(()=>serviceArtifact('linux','/tmp/a\nExecStart=bad','/tmp/private')).toThrow();
});
test('live IPC preserves expired lease, concurrent start loses cleanly, and unsafe socket releases own lease',async()=>{
 const {mkdtempSync,writeFileSync,rmSync}=await import('node:fs'),{tmpdir}=await import('node:os'),{join}=await import('node:path'),{createServer}=await import('node:net');
 const {Database}=await import('bun:sqlite'),{CloudStore}=await import('../src/cloud/persistence.ts'),{runCloudDaemon}=await import('../src/cloud/daemon.ts');
 const home=mkdtempSync(join(tmpdir(),'akc-lease-')),db=new Database(':memory:'),store=new CloudStore(db,new Uint8Array(32));
 const runtime={store,engine:{sync:async()=>{}}} as unknown as Parameters<typeof runCloudDaemon>[0];
 const socket=join(home,'cloud.sock');
 try{
  store.acquireLease('running',0,1,2);
  const server=createServer(s=>s.once('data',()=>s.end('ok\n')));await new Promise<void>(resolve=>server.listen(socket,resolve));
  await expect(runCloudDaemon(runtime,home,new globalThis.AbortController().signal)).rejects.toThrow('already_running');
  expect(db.query('SELECT owner FROM cloud_lease WHERE id=2').get()).toEqual({owner:'running'});
  await new Promise<void>(resolve=>server.close(()=>resolve()));store.releaseLease('running',2);
  writeFileSync(socket,'unsafe');await expect(runCloudDaemon(runtime,home,new globalThis.AbortController().signal)).rejects.toThrow('unsafe_cloud_socket');
  expect(db.query('SELECT * FROM cloud_lease').all()).toHaveLength(0);rmSync(socket);
  const abort=new globalThis.AbortController();const running=runCloudDaemon(runtime,home,abort.signal);
  await new Promise(resolve=>setTimeout(resolve,30));await expect(runCloudDaemon(runtime,home,new globalThis.AbortController().signal)).rejects.toThrow('already_running');
  abort.abort();await running;expect(db.query('SELECT * FROM cloud_lease').all()).toHaveLength(0);
 }finally{db.close();rmSync(home,{recursive:true,force:true});}
});
