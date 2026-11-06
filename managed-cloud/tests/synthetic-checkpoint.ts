// Test-only service: generated ephemeral keys never leave this Worker.
import { WorkerEntrypoint } from 'cloudflare:workers';
import { syntheticSigner } from './synthetic-signer.ts';
const signer = syntheticSigner();
export class CheckpointSigner extends WorkerEntrypoint {
    async publicKeys(){return [await this.key()];}
    async key() { return (await signer).key(); }
    async sign(canonical: string) { return (await signer).sign(canonical); }
}
export default { fetch() { return new Response(null, { status: 404 }); } };
