/* eslint-disable no-unused-vars -- parameter properties */
import {cc,FFIType} from 'bun:ffi';
import {constants,closeSync,fstatSync,mkdtempSync,writeFileSync,rmSync,readFileSync} from 'node:fs';
import source from '../../native/relative-directory.c' with {type:'file'};
import {tmpdir} from 'node:os';
import {dirname,basename,join} from 'node:path';
// POSIX *at primitives bind every operation to the caller's already opened directory.
// No pathname fallback is permitted on an unsupported platform.
const supported=process.platform==='darwin'||process.platform==='linux';
const library=supported?compile():null;
function compile(){
 const directory=mkdtempSync(join(tmpdir(),'akc-dirfd-code-')),file=join(directory,'relative.c');
 try{writeFileSync(file,readFileSync(source),{mode:0o600});return cc({source:file,define:process.platform==='darwin'?{AKC_DARWIN:'1'}:{},symbols:{
 akc_openat:{args:[FFIType.i32,FFIType.ptr,FFIType.i32,FFIType.u32],returns:FFIType.i32},
 akc_linkat:{args:[FFIType.i32,FFIType.ptr,FFIType.ptr],returns:FFIType.i32},
 akc_unlinkat:{args:[FFIType.i32,FFIType.ptr],returns:FFIType.i32},
}});}finally{rmSync(directory,{recursive:true,force:true});}
}
function result(n:number){
 if(n>=0)return n;
 throw Object.assign(new Error('cloud_export_output_conflict'),{code:n===-2?'ENOENT':'EIO'});
}
export class RelativeDirectory {
 constructor(private fd:number,private parent:string){if(!library)throw new Error('cloud_export_platform_unsupported');if(!fstatSync(fd).isDirectory())throw new Error('cloud_export_output_conflict');}
 private name(path:string){if(dirname(path)!==this.parent||['.','..',''].includes(basename(path))||path.includes('\0'))throw new Error('cloud_export_output_conflict');return Buffer.from(basename(path)+'\0');}
 open=(path:string,flags:number,mode=0o600)=>result(library!.symbols.akc_openat!(this.fd,this.name(path),flags|constants.O_NOFOLLOW,mode) as number);
 link=(source:string,target:string)=>{result(library!.symbols.akc_linkat!(this.fd,this.name(source),this.name(target)) as number);};
 unlink=(path:string)=>{result(library!.symbols.akc_unlinkat!(this.fd,this.name(path)) as number);};
 stat=(path:string)=>{const fd=this.open(path,constants.O_RDONLY|constants.O_NONBLOCK);try{return fstatSync(fd);}finally{closeSync(fd);}};
}
