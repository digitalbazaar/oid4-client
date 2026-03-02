/*
 * Copyright (c) 2025-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import {decode as cborDecode, encode as cborEncode, Token, Type} from 'cborg';
import {createNamedError, jwkToCoseKey, sha256} from '../util.js';
import {decrypt as hpkeDecrypt} from './hpke.js';

const TEXT_ENCODER = new TextEncoder();

/**
 * Encodes a `SessionTranscript` for use with mDL (ISO 18013-7 variants).
 *
 * The `handover` parameter's properties, other than `type`, depend on the
 * value of `type`:
 *
 * For 'AnnexBHandover':
 *   mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce
 * For 'OpenID4VPDCAPIHandover':
 *   origin, nonce, jwkThumbprint
 * For 'dcapi':
 *   nonce, recipientPublicKey.
 *
 * @param {object} options - The options.
 * @param {object} options.handover - The handover options to use in the
 *   session transcript, including the `type` and any type-specific properties;
 *   the `type` can be any of the following:
 *     'AnnexBHandover' for (ISO 18013-7 Annex B),
 *     'OpenID4VPDCAPIHandover' for ISO 18013-7 Annex D "Google DC API",
 *     'dcapi' for ISO 18013-7 Annex C "Apple DC API".
 *
 * @returns {Promise<Uint8Array>} The cbor-encoded session transcript.
 */
export async function encodeSessionTranscript({handover} = {}) {
  // produce `Handover` component of mDL session transcript
  let Handover;
  if(handover.type === 'AnnexBHandover') {
    Handover = await _encodeAnnexBHandover({handover});
  } else if(handover.type === 'OpenID4VPDCAPIHandover') {
    Handover = await _encodeAnnexDHandover({handover});
  } else if(handover.type === 'dcapi') {
    Handover = await _encodeAnnexCHandover({handover});
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

export async function decryptAnnexCResponse({
  base64urlEncryptedResponse, getDecryptParameters
} = {}) {
  // ISO 18013-7 Annex C, with hpke-encrypted payload
  const EncryptedResponse = cborDecode(
    base64url.decode(base64urlEncryptedResponse));
  const [protocol] = EncryptedResponse;
  if(protocol !== 'dcapi') {
    throw createNamedError({
      message: `Unsupported encryption protocol "${protocol}".`,
      name: 'NotSupportedError'
    });
  }
  const [, {enc, cipherText: ct}] = EncryptedResponse;
  return hpkeDecrypt({enc, ct, getDecryptParameters});
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

// encode `handover` as ISO 18013-7 Annex B Handover
async function _encodeAnnexBHandover({handover}) {
  const {
    mdocGeneratedNonce,
    clientId,
    responseUri,
    verifierGeneratedNonce
  } = handover;
  return [mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce];
}

// encode `handover` as ISO 18013-7 Annex C Handover
async function _encodeAnnexCHandover({handover}) {
  /* Details:

  Handover = `['dcapi', dcapiInfoHash]`
  dcapiInfo = [Base64EncryptionInfo, SerializedOrigin]

  SerializedOrigin = tstr
  dcapiInfoHash = bstr

  `Base64EncryptionInfo` is the base64url-no-pad encoding of the cbor-encoded
  `EncryptionInfo`.

  EncryptionInfo = [
    // encryption protocol identifier
    'dcapi',
    EncryptionParameters
  ]

  EncryptionParameters = {
    // binary string
    nonce,
    // COSE key
    recipientPublicKey
  }
  */
  const {origin, nonce} = handover;
  // if `recipientPublicKey` is not present, convert it from
  // `recipientPublicKeyJwk`
  const recipientPublicKey = handover.recipientPublicKey ??
    jwkToCoseKey({jwk: handover.recipientPublicJwk});
  const nonceBytes = typeof nonce === 'string' ?
    TEXT_ENCODER.encode(nonce) : nonce;
  const EncryptionParameters = [nonceBytes, recipientPublicKey];
  const EncryptionInfo = ['dcapi', EncryptionParameters];
  const Base64EncryptionInfo = base64url.encode(cborEncode(EncryptionInfo));
  const dcapiInfo = [Base64EncryptionInfo, origin];
  const dcapiInfoHash = await sha256(cborEncode(dcapiInfo));
  return ['dcapi', dcapiInfoHash];
}

// encode `handover` as ISO 18013-7 Annex D Handover
async function _encodeAnnexDHandover({handover}) {
  // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.6.2
  // for `"response_mode": "dc_api"`, `jwkThumbprint` MUST be `null`
  // for `"response_mode": "dc_api.jwt"`, `jwkThumbprint` MUST be the JWK
  // SHA-256 Thumbprint of the verifier's public key used to encrypt
  // the response (as a Uint8Array)
  const {origin, nonce} = handover;
  const jwkThumbprint = typeof handover.jwkThumbprint === 'string' ?
    base64url.decode(handover.jwkThumbprint) : handover.jwkThumbprint;
  const handoverInfo = [origin, nonce, jwkThumbprint];
  const handoverInfoHash = await sha256(cborEncode(handoverInfo));
  return ['OpenID4VPDCAPIHandover', handoverInfoHash];
}
