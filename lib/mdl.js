/*
 * Copyright (c) 2025-2026 Digital Bazaar, Inc. All rights reserved.
 */
import {encode as cborEncode, Token, Type} from 'cborg';

/**
 * Encodes a `SessionTranscript` for use with mDL (ISO 18013-7 variants).
 *
 * The `handover` parameter's properties, other than `type`, depend on the
 * value of `type`:
 *
 * For 'AnnexBHandover':
 *   mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce
 * For 'OpenID4VPDCAPIHandover':
 *   origin, clientId, nonce
 * For 'dcapi':
 *   nonce, recipientPublicKey.
 *
 * @param {object} options - The options.
 * @param {object} options.handover - The handover options to use in the
 *   session transcript, including the `type` and any type-specific properties;
 *   the `type` can be any of the following:
 *     'AnnexBHandover' for (ISO 18013-7 Annex B),
 *     'OpenID4VPDCAPIHandover' for ISO 18013-7 Annex D "Google DC API",
 *     'dcapi' for ISO 18013-7 Annex C "Apple API".
 *
 * @returns {Promise<Uint8Array>} The cbor-encoded session transcript.
 */
export async function encodeSessionTranscript({handover}) {
  // produce `Handover` component of mDL session transcript
  let Handover;
  if(handover.type === 'AnnexBHandover') {
    const {
      mdocGeneratedNonce,
      clientId,
      responseUri,
      verifierGeneratedNonce
    } = handover;
    // create ISO 18013-7 Annex B `Handover`
    Handover = [
      mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce
    ];
  } else if(handover.type === 'OpenID4VPDCAPIHandover') {
    // create ISO 18013-7 Annex D `Handover`
    // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.6.2
    const {origin, clientId, nonce} = handover;
    const handoverInfo = [origin, clientId, nonce];
    const handoverInfoBytes = cborEncode(handoverInfo);
    const handoverInfoHash = _sha256(handoverInfoBytes);
    Handover = ['OpenID4VPDCAPIHandover', handoverInfoHash];
  } else {
    throw new Error(`Unknown handover type "${handover.type}".`);
  }

  // create session transcript which is always:
  // `[DeviceEngagementBytes, EReaderKeyBytes, Handover]`
  // where `DeviceEngagementBytes` and `EReaderKeyBytes` are `null`
  const sessionTranscript = [null, null, Handover];

  // session transcript bytes are encoded as a CBOR data item within a byte
  // string (CBOR Tag 24):
  const dataItem = cborEncode(sessionTranscript);
  return cborEncode(dataItem, {
    typeEncoders: {Uint8Array: createTag24Encoder(dataItem)}
  });
}

async function _sha256(data) {
  const algorithm = {name: 'SHA-256'};
  return new Uint8Array(await crypto.subtle.digest(algorithm, data));
}

function createTag24Encoder(value) {
  return function tag24Encoder(obj) {
    if(obj !== value) {
      return null;
    }
    return [
      new Token(Type.tag, 24),
      new Token(Type.bytes, obj)
    ];
  };
}
