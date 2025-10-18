/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {_fromQueryByExampleQuery} from '../../lib/convert/index.js';
import chai from 'chai';

chai.should();
const {expect} = chai;

describe('convert', () => {
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
});
