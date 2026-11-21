/** Public fixture trust only. The test compiler overrides this module from
 * verified one-run fixture provenance; running source cannot opt in. */
import type {SignedManagedOperation} from '../../src/cloud/protocol.ts';
import type {ContinuationPilotBuildArtifact} from '../../src/cloud/continuation-pilot-build.ts';

export interface CompiledFixtureTrust {
 readonly artifact:ContinuationPilotBuildArtifact;
 readonly rootPublicKey:string;
 readonly helperAppendix:SignedManagedOperation;
 readonly fixtureRoot:string;
 readonly directory:{readonly device:string;readonly inode:string};
 readonly file:{readonly device:string;readonly inode:string;readonly size:string;readonly mode:string;readonly uid:string};
 readonly target:'darwin-arm64'|'darwin-x64';
}
export function compiledFixtureTrust():CompiledFixtureTrust|undefined{return undefined;}
