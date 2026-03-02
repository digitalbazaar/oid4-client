/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc. All rights reserved.
 */
import {
  Aes128Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  HkdfSha256
} from '@hpke/core';
import {createNamedError, selectJwk} from '../util.js';
import {importJWK} from 'jose';

// `enc`: encapsulated sender public key
// `ct`: cipher text
export async function decrypt({enc, ct, getDecryptParameters}) {
  if(typeof getDecryptParameters !== 'function') {
    throw new TypeError(
      '"getDecryptParameters" is required for "direct_post.jwt" ' +
      'response mode.');
  }

  // load decryption parameters
  const params = await getDecryptParameters({enc});
  const {keys} = params;
  let {getKey} = params;
  let recipientPublicJwk;
  if(!getKey) {
    // process `enc` to find key
    getKey = async ({enc}) => {
      // import sender key and export as JWK to find a matching recipient key
      // for decryption
      const jwk = await _rawPublicKeyToJwk({rawPublicKey: enc});
      const match = selectJwk({keys, kty: jwk.kty, crv: jwk.crv});
      if(!match) {
        throw createNamedError({
          message: 'No matching recipient cryptographic key found.',
          name: 'NotSupportedError',
          details: {httpStatusCode: 400, public: true}
        });
      }
      const {d, ...rest} = match;
      const recipientSecretJwk = {...rest, d};
      recipientPublicJwk = {alg: 'ECDH-ES', use: 'enc', ...rest};
      return importJWK(recipientSecretJwk, 'ECDH-ES', {extractable: true});
    };
  }
  const recipientKey = await getKey({enc});
  const info = await params?.getInfo?.({enc, recipientPublicJwk});
  const aad = await params?.getAad?.({enc, info, recipientPublicJwk});

  // open: ciphertext + encapsulated key => plaintext
  const suite = _createCiphersuite();
  const recipient = await suite.createRecipientContext({
    recipientKey, enc, info
  });
  const pt = new Uint8Array(await recipient.open(ct, aad));
  return {pt, recipientPublicJwk};
}

export async function encrypt({pt, info, aad, encryptionOptions}) {
  if(encryptionOptions?.enc && !(encryptionOptions.enc !== 'A128GCM')) {
    throw createNamedError({
      message:
        `Unsupported encryption algorithm "${encryptionOptions.enc}"; ` +
        'only "A128GCM" is supported.',
      name: 'DataError'
    });
  }

  // import recipient public key
  const {recipientPublicJwk} = encryptionOptions;
  const recipientPublicKey = await importJWK(recipientPublicJwk, 'ECDH-ES');

  // seal: plaintext => ciphertext + encapsulated key
  const suite = _createCiphersuite();
  const sender = await suite.createSenderContext({
    recipientPublicKey, info
  });
  const ct = await sender.seal(pt, aad);
  return {enc: sender.enc, ct};
}

// only supported cipher suite
function _createCiphersuite() {
  return new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm()
  });
}

async function _rawPublicKeyToJwk({rawPublicKey}) {
  try {
    const publicKey = await globalThis.crypto.subtle.importKey(
      'raw', rawPublicKey, {name: 'ECDH', namedCurve: 'P-256'},
      true, []);
    const jwk = await globalThis.crypto.subtle.exportKey('jwk', publicKey);
    return jwk;
  } catch(e) {
    throw createNamedError({
      message:
        'Unsupported public key; it must be "ECDH-ES" with curve "P-256".',
      name: 'NotSupportedError',
      details: {httpStatusCode: 400, public: true}
    });
  }
}
