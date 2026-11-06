export type EmailPurpose='invitation'|'recovery';
export function emailContext(purpose:unknown,context:unknown): asserts purpose is EmailPurpose {
 if(!['invitation','recovery'].includes(purpose as string)||typeof context!=='string'||!/^[a-f0-9]{64}$/.test(context))throw new Error('invalid_email_request');
}
export function normalizedEmail(value:unknown):string {
 if(typeof value!=='string'||value.length>254||! /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/.test(value))throw new Error('invalid_email_request');
 const [local,host]=value.split('@');
 if(local!.startsWith('.')||local!.endsWith('.')||local!.includes('..')||host!.split('.').some(label=>label.length>63))throw new Error('invalid_email_request');
 return value.toLowerCase();
}
/** Context is assembled by the API, never trusted from a submitted proof. */
export function emailProof(purpose:EmailPurpose,context:string,code:string){emailContext(purpose,context);return JSON.stringify([purpose,context,code]);}
