/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc. All rights reserved.
 */
import {createNamedError, selectJwk} from '../util.js';
import {EncryptJWT, importJWK, jwtDecrypt} from 'jose';

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
        throw createNamedError({
          message: `Unsupported algorithm "${protectedHeader.alg}"; ` +
            'algorithm must be "ECDH-ES".',
          name: 'NotSupportedError',
          details: {httpStatusCode: 400, public: true}
        });
      }
      const {d, ...rest} = selectJwk({keys, kid: protectedHeader.kid});
      const recipientSecretJwk = {...rest, d};
      recipientPublicJwk = {alg: 'ECDH-ES', use: 'enc', ...rest};
      return importJWK(recipientSecretJwk, 'ECDH-ES');
    };
  }

  try {
    const {payload, protectedHeader} = await jwtDecrypt(jwt, getKey, {
      // only supported algorithms at this time:
      contentEncryptionAlgorithms: ['A256GCM', 'A128GCM'],
      keyManagementAlgorithms: ['ECDH-ES']
    });
    return {payload, protectedHeader, recipientPublicJwk};
  } catch(cause) {
    throw createNamedError({
      message: `Decryption failed.`,
      name: 'DataError',
      details: {httpStatusCode: 400, public: true},
      cause
    });
  }
}

export async function encrypt({payload, encryptionOptions}) {
  const {keyManagementParameters, recipientPublicJwk} = encryptionOptions;
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
