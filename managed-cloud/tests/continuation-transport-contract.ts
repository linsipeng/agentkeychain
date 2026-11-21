/** Wire bytes used only by the synthetic Worker graph. */
export const fixtureTransportOrigin='https://continuation-transport.fixture.invalid';
export interface PostExpectation {nonce:string;requestDigest:string;mainCommitDigest:string;priorFreshHeadDigest:string}
export const canonicalFixturePost=(x:PostExpectation)=>JSON.stringify({nonce:x.nonce,requestDigest:x.requestDigest,
 mainCommitDigest:x.mainCommitDigest,priorFreshHeadDigest:x.priorFreshHeadDigest});
