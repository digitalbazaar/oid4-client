/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import {httpClient} from '@digitalbazaar/http-client';

const TEXT_ENCODER = new TextEncoder();
const ENCODED_PERIOD = TEXT_ENCODER.encode('.');

export function assert(x, name, type, optional = false) {
  const article = type === 'object' ? 'an' : 'a';
  if(x !== undefined && typeof x !== type) {
    throw new TypeError(
      `${optional ? 'When present, ' : ''} ` +
      `"${name}" must be ${article} ${type}.`);
  }
}

export function assertOptional(x, name, type) {
  return assert(x, name, type, true);
}

export function base64Decode(str) {
  if(Uint8Array.fromBase64) {
    return Uint8Array.fromBase64(str);
  }
  return base64url.decode(
    str.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'));
}

export function base64Encode(data) {
  if(data.toBase64) {
    return data.toBase64();
  }
  // note: this is base64-no-pad; will only work with specific data lengths
  return base64url.encode(data).replace(/-/g, '+').replace(/_/g, '/');
}

export function createNamedError({message, name, details, cause} = {}) {
  const error = new Error(message, {cause});
  error.name = name;
  if(details) {
    error.details = details;
  }
  return error;
}

export function fetchJSON({url, agent} = {}) {
  // allow these params to be passed / configured
  const fetchOptions = {
    // max size for issuer config related responses (in bytes, ~4 KiB)
    size: 4096,
    // timeout in ms for fetching an issuer config
    timeout: 5000,
    agent
  };

  return httpClient.get(url, fetchOptions);
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

export function selectJwk({keys, kid, alg, kty, crv, use} = {}) {
  /* Example JWKs "keys":
  "jwks": {
    "keys": [
      {
        "kty": "EC",
        "use": "enc",
        "crv": "P-256",
        "x": "...",
        "y": "...",
        "alg": "ECDH-ES",
        "kid": "..."
      }
    ]
  } */
  if(!Array.isArray(keys)) {
    return;
  }

  // match `kid` exactly if given
  if(kid !== undefined) {
    return keys.find(jwk => jwk?.kid === kid);
  }

  return keys.find(jwk => {
    // default unspecified search values to whatever is in `jwk`
    const alg1 = alg ?? jwk.alg;
    const kty1 = kty ?? jwk.kty;
    const crv1 = crv ?? jwk.crv;
    const use1 = use ?? jwk.use;
    const {
      // default missing `alg` value in `jwk` to search value
      alg: alg2 = alg1,
      kty: kty2,
      crv: crv2,
      // default missing `use` value in `jwk` to search value
      use: use2 = use1
    } = jwk;
    // return if `jwk` matches computed values
    return alg1 === alg2 && kty1 === kty2 && crv1 === crv2 && use1 === use2;
  });
}

export async function signJWT({payload, protectedHeader, signer} = {}) {
  // encode payload and protected header
  const b64Payload = base64url.encode(JSON.stringify(payload));
  const b64ProtectedHeader = base64url.encode(JSON.stringify(protectedHeader));
  payload = TEXT_ENCODER.encode(b64Payload);
  protectedHeader = TEXT_ENCODER.encode(b64ProtectedHeader);

  // concatenate
  const data = new Uint8Array(
    protectedHeader.length + ENCODED_PERIOD.length + payload.length);
  data.set(protectedHeader);
  data.set(ENCODED_PERIOD, protectedHeader.length);
  data.set(payload, protectedHeader.length + ENCODED_PERIOD.length);

  // sign
  const signature = await signer.sign({data});

  // create JWS
  const jws = {
    signature: base64url.encode(signature),
    payload: b64Payload,
    protected: b64ProtectedHeader
  };

  // create compact JWT
  return `${jws.protected}.${jws.payload}.${jws.signature}`;
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
