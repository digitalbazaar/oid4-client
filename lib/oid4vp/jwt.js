/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc. All rights reserved.
 */
import {createNamedError, selectJwk} from '../util.js';
import {EncryptJWT, importJWK, jwtDecrypt} from 'jose';

const TEXT_ENCODER = new TextEncoder();

export async function decrypt({jwt, getDecryptParameters}) {
  if(typeof getDecryptParameters !== 'function') {
    throw new TypeError(
      '"getDecryptParameters" is required for "direct_post.jwt" ' +
      'response mode.');
  }

  const params = await getDecryptParameters({jwt});
  const {keys} = params;
  let {getKey} = params;
  let recipientPublicJwk;
  if(!getKey) {
    // note: `jose` lib's JWK key set feature cannot be used and passed to
    // `jwtDecrypt()` as the second parameter because the expected `alg`
    // "ECDH-ES" is not a unsupported algorithm for selecting a key from a set
    getKey = protectedHeader => {
      if(protectedHeader.alg !== 'ECDH-ES') {
        const error = createNamedError({
          message: `Unsupported algorithm "${protectedHeader.alg}"; ` +
            'algorithm must be "ECDH-ES".',
          name: 'NotSupportedError',
          details: {httpStatusCode: 400, public: true}
        });
        throw error;
      }
      const {d, ...rest} = selectJwk({keys, kid: protectedHeader.kid});
      const recipientSecretJwk = {...rest, d};
      recipientPublicJwk = rest;
      return importJWK(recipientSecretJwk, 'ECDH-ES');
    };
  }

  const {payload, protectedHeader} = await jwtDecrypt(jwt, getKey, {
    // only supported algorithms at this time:
    contentEncryptionAlgorithms: ['A256GCM', 'A128GCM'],
    keyManagementAlgorithms: ['ECDH-ES']
  });

  return {payload, protectedHeader, recipientPublicJwk};
}

export async function encrypt({
  payload, authorizationRequest, encryptionOptions
}) {
  // configure `keyManagementParameters` for `EncryptJWT` API
  const keyManagementParameters = {};
  if(encryptionOptions?.mdl?.handover) {
    // ISO 18013-7 Annex B has specific handover params for apu + apv; for
    // Annex D generate `apu` and use `nonce` for `apv` but this isn't a
    // requirement; Annex C uses HPKE not a JWT so not relevant here
    const {
      mdocGeneratedNonce,
      nonce,
      verifierGeneratedNonce
    } = encryptionOptions.mdl.handover;

    // generate 128-bit random `apu` if no `mdocGeneratedNonce` provided
    const apu = mdocGeneratedNonce ??
      globalThis.crypto.getRandomValues(new Uint8Array(16));
    // default to using `authorizationRequest.nonce` for verifier nonce
    const apv = verifierGeneratedNonce ?? nonce ?? authorizationRequest.nonce;
    // note: `EncryptJWT` API requires `apu/apv` (`partyInfoU`/`partyInfoV`)
    // to be passed as Uint8Arrays; they will be encoded using `base64url` by
    // that API
    keyManagementParameters.apu = typeof apu === 'string' ?
      TEXT_ENCODER.encode(apu) : apu;
    keyManagementParameters.apv = typeof apv === 'string' ?
      TEXT_ENCODER.encode(apv) : apv;
  }

  const {recipientPublicJwk} = encryptionOptions;
  const jwt = await new EncryptJWT(payload)
    .setProtectedHeader({
      alg: 'ECDH-ES',
      enc: encryptionOptions?.enc ?? 'A256GCM',
      kid: recipientPublicJwk.kid
    })
    .setKeyManagementParameters(keyManagementParameters)
    .encrypt(recipientPublicJwk);
  return jwt;
}
