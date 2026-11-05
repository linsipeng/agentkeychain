import { WorkerEntrypoint } from 'cloudflare:workers';
export class Custodian extends WorkerEntrypoint<{
    CUSTODIAN: D1Database;
}> {
    override async fetch() { return new Response(null, { status: 404 }); }
    async describe() { return { component: 'custodian', protocol: 1, recoveryEnabled: false, bindings: Object.keys(this.env).sort() }; }
}
export default { fetch() { return new Response(null, { status: 404 }); } };
