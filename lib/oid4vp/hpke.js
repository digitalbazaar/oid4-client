/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc. All rights reserved.
 */
import {
  Aes128Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  HkdfSha256
} from '@hpke/core';

const TEXT_DECODER = new TextDecoder();
const TEXT_ENCODER = new TextEncoder();

export async function decrypt({ct, getDecryptParameters}) {
  if(typeof getDecryptParameters !== 'function') {
    throw new TypeError(
      '"getDecryptParameters" is required for "direct_post.jwt" ' +
      'response mode.');
  }

  // const params = await getDecryptParameters({ct});
  // const {keys} = params;
  // let {getKey} = params;
  // let recipientPublicJwk;
  // if(!getKey) {
  // }

  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm()
  });

  const rkp = await suite.kem.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey
  });

  // FIXME: adjust to match Annex C requirements
  //const {recipientPublicJwk} = encryptionOptions;
  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc
  });

  const pt = await recipient.open(ct);
  const payload = TEXT_DECODER.decode(pt);

  return {payload};//, recipientPublicJwk};
}

export async function encrypt({
  vpToken, presentationSubmission/*, authorizationRequest, encryptionOptions*/
}) {
  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm()
  });

  const rkp = await suite.kem.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey
  });

  //const {recipientPublicJwk} = encryptionOptions;

  // encrypt
  // FIXME: adjust to match Annex C requirements
  const claimSet = {
    vp_token: vpToken,
    presentation_submission: presentationSubmission
  };
  const ct = await sender.seal(TEXT_ENCODER.encode(claimSet));
  return ct;
}
