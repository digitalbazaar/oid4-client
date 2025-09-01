/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
//import * as base64url from 'base64url-universal';
import * as mdlUtils from '../mdlUtils.js';
import {_fromQueryByExampleQuery} from '../../lib/oid4vp.js';
import chai from 'chai';
import {generateCertificateChain} from '../certUtils.js';

chai.should();
const {expect} = chai;

describe('OID4VP', () => {
  describe('QueryByExample => Presentation Definition', () => {
    it('should NOT include "vc" prefix in paths', async () => {
      const presentation_definition = _fromQueryByExampleQuery({
        credentialQuery: {
          reason: 'Please present your Driver\'s License to complete the ' +
            'verification process.',
          example: {
            '@context': [
              'https://www.w3.org/2018/credentials/v1',
              'https://w3id.org/vdl/v1',
              'https://w3id.org/vdl/aamva/v1'
            ],
            type: [
              'Iso18013DriversLicenseCredential'
            ]
          }
        },
        prefixJwtVcPath: false
      });
      expect(presentation_definition.constraints.fields[0].path).to.eql(
        ['$[\'@context\']']);
      expect(presentation_definition.constraints.fields[1].path).to.eql(
        ['$[\'type\']']);
    });

    it('should include "vc" prefix in paths', async () => {
      const presentation_definition = _fromQueryByExampleQuery({
        credentialQuery: {
          reason: 'Please present your Driver\'s License to complete the ' +
            'verification process.',
          example: {
            '@context': [
              'https://www.w3.org/2018/credentials/v1',
              'https://w3id.org/vdl/v1',
              'https://w3id.org/vdl/aamva/v1'
            ],
            type: [
              'Iso18013DriversLicenseCredential'
            ]
          }
        },
        prefixJwtVcPath: true
      });
      expect(presentation_definition.constraints.fields[0].path).to.eql([
        '$[\'@context\']',
        '$[\'vc\'][\'@context\']'
      ]);
      expect(presentation_definition.constraints.fields[1].path).to.eql([
        '$[\'type\']',
        '$[\'vc\'][\'type\']'
      ]);
    });

    it('auto-detect to NOT include "vc" w/unspecified security', async () => {
      const presentation_definition = _fromQueryByExampleQuery({
        credentialQuery: {
          reason: 'Please present your Driver\'s License to complete the ' +
            'verification process.',
          example: {
            '@context': [
              'https://www.w3.org/2018/credentials/v1',
              'https://w3id.org/vdl/v1',
              'https://w3id.org/vdl/aamva/v1'
            ],
            type: [
              'Iso18013DriversLicenseCredential'
            ]
          }
        }
      });
      expect(presentation_definition.constraints.fields[0].path).to.eql(
        ['$[\'@context\']']);
      expect(presentation_definition.constraints.fields[1].path).to.eql(
        ['$[\'type\']']);
    });

    it('auto-detect to NOT include "vc" w/acceptedCryptosuites', async () => {
      const presentation_definition = _fromQueryByExampleQuery({
        credentialQuery: {
          reason: 'Please present your Driver\'s License to complete the ' +
            'verification process.',
          example: {
            '@context': [
              'https://www.w3.org/2018/credentials/v1',
              'https://w3id.org/vdl/v1',
              'https://w3id.org/vdl/aamva/v1'
            ],
            type: [
              'Iso18013DriversLicenseCredential'
            ]
          },
          acceptedCryptosuites: ['bbs-2023']
        }
      });
      expect(presentation_definition.constraints.fields[0].path).to.eql(
        ['$[\'@context\']']);
      expect(presentation_definition.constraints.fields[1].path).to.eql(
        ['$[\'type\']']);
    });

    it('auto-detect to include "vc" w/acceptedEnvelopes', async () => {
      const presentation_definition = _fromQueryByExampleQuery({
        credentialQuery: {
          reason: 'Please present your Driver\'s License to complete the ' +
            'verification process.',
          example: {
            '@context': [
              'https://www.w3.org/2018/credentials/v1',
              'https://w3id.org/vdl/v1',
              'https://w3id.org/vdl/aamva/v1'
            ],
            type: [
              'Iso18013DriversLicenseCredential'
            ]
          },
          acceptedEnvelopes: ['application/jwt']
        }
      });
      expect(presentation_definition.constraints.fields[0].path).to.eql([
        '$[\'@context\']',
        '$[\'vc\'][\'@context\']'
      ]);
      expect(presentation_definition.constraints.fields[1].path).to.eql([
        '$[\'type\']',
        '$[\'vc\'][\'type\']'
      ]);
    });

    it('auto-detect to include "vc" w/both "accepted" methods', async () => {
      const presentation_definition = _fromQueryByExampleQuery({
        credentialQuery: {
          reason: 'Please present your Driver\'s License to complete the ' +
            'verification process.',
          example: {
            '@context': [
              'https://www.w3.org/2018/credentials/v1',
              'https://w3id.org/vdl/v1',
              'https://w3id.org/vdl/aamva/v1'
            ],
            type: [
              'Iso18013DriversLicenseCredential'
            ]
          },
          acceptedCryptosuites: ['bbs-2023'],
          acceptedEnvelopes: ['application/jwt']
        }
      });
      expect(presentation_definition.constraints.fields[0].path).to.eql([
        '$[\'@context\']',
        '$[\'vc\'][\'@context\']'
      ]);
      expect(presentation_definition.constraints.fields[1].path).to.eql([
        '$[\'type\']',
        '$[\'vc\'][\'type\']'
      ]);
    });
  });

  describe.only('ISO 18013-7', () => {
    it('should pass', async () => {
      // get device key pair
      const deviceKeyPair = await mdlUtils.generateDeviceKeyPair();

      // create a certificate chain that ends in the MDL issuer (leaf)
      const certChain = await generateCertificateChain();

      // issue an example MDL
      const issuerPrivateJwk = certChain.leaf.subject.jwk;
      const issuerCertificate = certChain.leaf.pemCertificate;
      const mdoc = await mdlUtils.issue({
        issuerPrivateJwk, issuerCertificate,
        devicePublicJwk: deviceKeyPair.publicJwk
      });

      // generate example verifier identity and cert chain...

      /*
      // auto-generate `x5c` that includes public key for signing key
      const certificateChainEntities = await generateCertificateChain({
        leafConfig: {dnsName: 'test.domain.example'}
      });
      const x5c = [certificateChainEntities.leaf.b64Certificate];
      // trusted certs for verifying authz request, NOT for verifying mDL
      const trustedCertificates = [
        certificateChainEntities.intermediate.pemCertificate,
        certificateChainEntities.root.pemCertificate
      ];
      */

      // create example presentation defintion from verifier
      const presentationDefinition = {
        id: 'mdl-test-age-over-21',
        input_descriptors: [
          {
            id: 'org.iso.18013.5.1.mDL',
            format: {
              mso_mdoc: {
                alg: ['ES256']
              }
            },
            constraints: {
              limit_disclosure: 'required',
              fields: [
                {
                  // eslint-disable-next-line quotes
                  path: ["$['org.iso.18013.5.1']['age_over_21']"],
                  intent_to_retain: false
                }
              ]
            }
          }
        ]
      };

      // create an MDL session transcript
      const sessionTranscript = {
        mdocGeneratedNonce: crypto.randomUUID(),
        clientId: crypto.randomUUID(),
        // note: expected to be an OID4VP exchange response URL
        responseUri: 'https://test.domain/example/authz/response',
        verifierGeneratedNonce: crypto.randomUUID()
      };

      // create MDL "device response" presentation
      const deviceResponse = await mdlUtils.createDeviceResponse({
        presentationDefinition,
        mdoc,
        sessionTranscript,
        devicePrivateJwk: deviceKeyPair.privateJwk
      });

      // set `vpToken` to base64url-no-pad-encoded device response
      //const vpToken = base64url.encode(deviceResponse);

      // FIXME: create authz response

      // FIXME: parse authz response

      // FIXME: verify presentation
      await mdlUtils.verifyPresentation({
        deviceResponse, sessionTranscript,
        trustedCertificates: [certChain.intermediate.pemCertificate]
      });
    });
  });
});
