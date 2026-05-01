/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc.
 */
import {createPresentation, signPresentation} from '@digitalbazaar/vc';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {cryptosuite as ecdsaRdfc2019CryptoSuite} from
  '@digitalbazaar/ecdsa-rdfc-2019-cryptosuite';
import {cryptosuite as eddsaRdfc2022CryptoSuite} from
  '@digitalbazaar/eddsa-rdfc-2022-cryptosuite';
import {signJWT} from '../util.js';

export async function generateDIDProofDIVP({
  did, signer, challenge, domain
} = {}) {
  const {id} = signer;
  const holder = did ?? id?.includes('#') ? id.slice(0, id.indexOf('#')) : id;
  const presentation = createPresentation({holder});
  return signPresentation({
    presentation,
    suite: _createDataIntegrityProof({signer}),
    domain,
    challenge
  });
}

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

function _createDataIntegrityProof({signer}) {
  const {algorithm} = signer;

  let cryptosuite;
  if(algorithm === 'Ed25519' || algorithm === 'EdDSA') {
    cryptosuite = eddsaRdfc2022CryptoSuite;
  } else if(algorithm?.startsWith('P-')) {
    cryptosuite = ecdsaRdfc2019CryptoSuite;
  } else {
    // default
    cryptosuite = eddsaRdfc2022CryptoSuite;
  }

  return new DataIntegrityProof({signer, cryptosuite});
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
