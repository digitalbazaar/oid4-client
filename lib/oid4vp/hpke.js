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

const TEXT_DECODER = new TextDecoder();
const TEXT_ENCODER = new TextEncoder();

// `enc`: encapsulated public key
// `ct`: cipher text
export async function decrypt({enc, ct, getDecryptParameters}) {
  if(typeof getDecryptParameters !== 'function') {
    throw new TypeError(
      '"getDecryptParameters" is required for "direct_post.jwt" ' +
      'response mode.');
  }

  // load recipient secret key
  const params = await getDecryptParameters({enc});
  const {keys} = params;
  let {getKey} = params;
  let recipientPublicJwk;
  if(!getKey) {
    // FIXME: process `enc`
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

  // open: ciphertext + encapsulated key => plaintext
  const suite = _createCiphersuite();
  const recipientKey = await getKey({enc});
  const recipient = await suite.createRecipientContext({recipientKey, enc});
  const pt = await recipient.open(ct);
  const payload = TEXT_DECODER.decode(pt);
  return {payload, recipientPublicJwk};
}

export async function encrypt({
  payload/*, authorizationRequest*/, encryptionOptions
}) {
  // FIXME: adjust `payload` and other params to match hpke requirements
  // `info`, `pt`, `aad`

  // import recipient public key
  const {recipientPublicJwk} = encryptionOptions;
  const recipientPublicKey = await importJWK(recipientPublicJwk, 'ECDH-ES');

  // seal: plaintext => ciphertext + encapsulated key
  const suite = _createCiphersuite();
  const sender = await suite.createSenderContext({recipientPublicKey});
  const ct = await sender.seal(TEXT_ENCODER.encode(payload));
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
