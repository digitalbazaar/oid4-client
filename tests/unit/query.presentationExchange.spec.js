/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {
  _fromQueryByExampleQuery
} from '../../lib/query/presentationExchange.js';
import chai from 'chai';

chai.should();
const {expect} = chai;

describe('query.presentationExchange', () => {
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
      expect(presentation_definition.submission_requirements).to.not.exist;
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
      expect(presentation_definition.submission_requirements).to.not.exist;
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
      expect(presentation_definition.submission_requirements).to.not.exist;
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
      expect(presentation_definition.submission_requirements).to.not.exist;
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
      expect(presentation_definition.submission_requirements).to.not.exist;
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
      expect(presentation_definition.submission_requirements).to.not.exist;
      expect(presentation_definition.constraints.fields[0].path).to.eql([
        '$[\'@context\']',
        '$[\'vc\'][\'@context\']'
      ]);
      expect(presentation_definition.constraints.fields[1].path).to.eql([
        '$[\'type\']',
        '$[\'vc\'][\'type\']'
      ]);
    });

    it('should process deep query', async () => {
      const presentation_definition = _fromQueryByExampleQuery({
        credentialQuery: {
          reason: `Please present your child's birth certificate to complete ` +
            'the verification process.',
          example: {
            '@context': [
              'https://www.w3.org/ns/credentials/v2',
              'https://w3id.org/vital-records/v1rc4'
            ],
            type: [
              'BirthCertificateCredential'
            ],
            credentialSubject: {
              type: 'BirthCertificate',
              certifier: {},
              newborn: {
                name: '',
                birthDate: '',
                parent: [{
                  name: 'John Doe'
                }]
              }
            }
          }
        }
      });
      expect(presentation_definition.submission_requirements).to.not.exist;
      expect(presentation_definition.constraints.fields[0].path).to.eql(
        ['$[\'@context\']']);
      expect(presentation_definition.constraints.fields[1].path).to.eql(
        ['$[\'type\']']);
      expect(presentation_definition.constraints.fields).to.deep.equal([
        {
          path: [
            '$[\'@context\']'
          ],
          filter: {
            type: 'array',
            allOf: [
              {
                contains: {
                  type: 'string',
                  const: 'https://www.w3.org/ns/credentials/v2'
                }
              },
              {
                contains: {
                  type: 'string',
                  const: 'https://w3id.org/vital-records/v1rc4'
                }
              }
            ]
          }
        }, {
          path: [
            '$[\'type\']'
          ],
          filter: {
            type: 'array',
            allOf: [
              {
                contains: {
                  type: 'string',
                  const: 'BirthCertificateCredential'
                }
              }
            ]
          }
        }, {
          path: [
            '$[\'credentialSubject\'][\'type\']'
          ],
          filter: {
            type: 'string',
            const: 'BirthCertificate'
          }
        }, {
          path: [
            '$[\'credentialSubject\'][\'certifier\']'
          ],
          filter: {
            type: 'object'
          }
        }, {
          path: [
            '$[\'credentialSubject\'][\'newborn\'][\'name\']'
          ],
          filter: {
            type: 'string',
            const: ''
          }
        }, {
          path: [
            '$[\'credentialSubject\'][\'newborn\'][\'birthDate\']'
          ],
          filter: {
            type: 'string',
            const: ''
          }
        }, {
          path: [
            '$[\'credentialSubject\'][\'newborn\'][\'parent\']'
          ],
          filter: {
            type: 'array',
            allOf: [
              {
                contains: {
                  type: 'object'
                }
              }
            ]
          }
        }
      ]);
    });
  });
});
