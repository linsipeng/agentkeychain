import {verifyInstalledContinuationPilot} from '../cloud/continuation-pilot-build.ts';
import {installedContinuationPilotTransport} from '../cloud/continuation-pilot-transport.ts';
import {installedPilotArtifact} from './continuation-pilot.generated.ts';

async function main(){
 // The gate is intentionally the only command. No vault, Keychain, browser,
 // network, test graph, environment configuration or ordinary CLI dispatch.
 const argv=process.argv.slice(2);
 if(argv.length!==1||argv[0]!=='check-installation')throw new Error('cloud_continuation_pilot_transport_unavailable');
 const installed=installedPilotArtifact();
 if(!installed)throw new Error('cloud_continuation_pilot_not_provisioned');
 const {artifact,rootPublicKey}=installed;
 const result=await verifyInstalledContinuationPilot(artifact,rootPublicKey,`${process.platform}-${process.arch}`);
 process.stdout.write(JSON.stringify({state:installedContinuationPilotTransport(result).state,...result})+'\n');
}

main().catch((error:unknown)=>{
 const code=error instanceof Error&&error.message==='cloud_continuation_pilot_transport_unavailable'?
  error.message:'cloud_continuation_pilot_not_provisioned';
 process.stderr.write(code+'\n');process.exitCode=1;
});
