/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {signJWT} from '../util.js';

export async function generateDIDProofJWT({
  signer, nonce, iss, aud, exp, nbf
} = {}) {
  /* Example:
  {
    "alg": "ES256",
    "kid":"did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1"
  }.
  {
    "iss": "s6BhdRkqt3",
    "aud": "https://server.example.com",
    "iat": 1659145924,
    "nonce": "tZignsnFbp"
  }
  */

  if(exp === undefined) {
    // default to 5 minute expiration time
    exp = Math.floor(Date.now() / 1000) + 60 * 5;
  }
  if(nbf === undefined) {
    // default to now
    nbf = Math.floor(Date.now() / 1000);
  }

  const {id: kid} = signer;
  const alg = _curveToAlg(signer.algorithm);
  const payload = {nonce, iss, aud, exp, nbf};
  const protectedHeader = {alg, kid};

  return signJWT({payload, protectedHeader, signer});
}

function _curveToAlg(crv) {
  if(crv === 'Ed25519' || crv === 'Ed448') {
    return 'EdDSA';
  }
  if(crv?.startsWith('P-')) {
    return `ES${crv.slice(2)}`;
  }
  if(crv === 'secp256k1') {
    return 'ES256K';
  }
  return crv;
}
