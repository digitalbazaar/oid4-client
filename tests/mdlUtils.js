/*
 * Copyright (c) 2025-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import {
  DeviceResponse, Document, MDoc, /*parse,*/ Verifier
} from '@auth0/mdl';
import {base64Encode} from '../lib/util.js';
import {encodeSessionTranscript} from '../lib/mdl.js';

const VC_CONTEXT_2 = 'https://www.w3.org/ns/credentials/v2';

const MDL_NAMESPACE = 'org.iso.18013.5.1';
const MDOC_TYPE_MDL = `${MDL_NAMESPACE}.mDL`;

export async function createDeviceResponse({
  presentationDefinition,
  mdoc, handover, devicePrivateJwk
} = {}) {
  devicePrivateJwk = {alg: 'ES256', ...devicePrivateJwk};
  const deviceResponse = await DeviceResponse.from(mdoc)
    // FIXME: OID4VP 1.0+ does not use presentation definition
    .usingPresentationDefinition(presentationDefinition)
    .usingSessionTranscriptBytes(await encodeSessionTranscript({handover}))
    .authenticateWithSignature(devicePrivateJwk, 'ES256')
    .sign();
  //console.log('Device response', deviceResponse);

  return new Uint8Array(deviceResponse.encode());
}

export async function createPresentation({
  presentationDefinition, mdoc, handover, devicePrivateJwk
} = {}) {
  const deviceResponse = await createDeviceResponse({
    mdoc, presentationDefinition, handover, devicePrivateJwk
  });

  // FIXME: define a base64url-encoded mdl vp token mime type?
  const encodedDeviceResponse = deviceResponse.encode();
  const vpToken = base64url.encode(encodedDeviceResponse);
  // console.log('device side: device response cbor', encodedDeviceResponse);
  // console.log(vpToken, 'vpToken');

  return {
    '@context': [VC_CONTEXT_2],
    id: `data:application/mdl-vp-token,${vpToken}`,
    type: 'EnvelopedVerifiablePresentation'
  };
}

export async function generateDeviceKeyPair() {
  // FIXME: generate new key pair each time
  const publicJwk = {
    kty: 'EC',
    x: 'QiUaYhZak1NubJEphQWmafykivrD80D2IpwqkkCU0oQ',
    y: 'sdNfR3813hzaUqF3-kWWOjI1xtSEqb93-graWFK-bA4',
    crv: 'P-256'
  };
  const privateJwk = {
    ...publicJwk,
    d: 'V729tbSdAGAL34Gqt2lGFM0Y9qrxILDUVheFduEkgFU'
  };
  return {publicJwk, privateJwk};
}

export async function issue({
  issuerPrivateJwk, issuerCertificate,
  devicePublicJwk
} = {}) {
  issuerPrivateJwk = {alg: 'ES256', ...issuerPrivateJwk};
  const document = await new Document(MDOC_TYPE_MDL)
    .addIssuerNameSpace(MDL_NAMESPACE, {
      family_name: 'FamilyName',
      given_name: 'GivenName',
      birth_date: '1990-01-01',
      age_over_21: true
    })
    .useDigestAlgorithm('SHA-256')
    .addValidityInfo({signed: new Date()})
    .addDeviceKeyInfo({deviceKey: devicePublicJwk})
    .sign({
      issuerPrivateKey: issuerPrivateJwk,
      issuerCertificate,
      kid: issuerPrivateJwk.kid,
      alg: 'ES256'
    });
  return new MDoc([document]);
}

export async function verifyPresentation({
  deviceResponse, handover, trustedCertificates
} = {}) {
  // uncomment to debug:
  /*const parsed = parse(deviceResponse);
  const issuerCertificate = parsed.documents?.[0]
    .issuerSigned?.issuerAuth?.certificate;
  console.log('issuer certificate', issuerCertificate);*/

  // produced on the verifier side
  const encodedSessionTranscript = await encodeSessionTranscript({handover});

  const verifier = new Verifier(trustedCertificates);
  // console.log('Getting diagnostic information...');
  // const diagnostic = await verifier.getDiagnosticInformation(
  //   deviceResponse, {encodedSessionTranscript});
  // console.debug('Diagnostic information:', diagnostic);

  try {
    const mdoc = await verifier.verify(deviceResponse, {
      encodedSessionTranscript
    });
    // console.log('Verification succeeded!');
    // console.log('Verified mdoc', mdoc);
    // console.log('DeviceSignedDocument', mdoc.documents[0]);

    // express cbor-encoded mdoc as an enveloped VC in a VP
    const encodedMdoc = new Uint8Array(mdoc.encode());
    const b64Mdl = base64Encode(encodedMdoc);
    return {
      '@context': [VC_CONTEXT_2],
      type: 'VerifiablePresentation',
      verifiableCredential: [{
        id: `data:application/mdl;base64,${b64Mdl}`,
        type: 'EnvelopedVerifiableCredential'
      }]
    };
  } catch(err) {
    //console.error('Verification failed:', err);
    throw err;
  }
}
