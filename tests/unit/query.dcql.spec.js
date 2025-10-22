/*!
 * Copyright (c) 2025 Digital Bazaar, Inc. All rights reserved.
 */
import {
  _fromQueryByExampleQuery
} from '../../lib/query/dcql.js';
import chai from 'chai';

chai.should();
const {expect} = chai;

describe('query.dcql', () => {
  describe('QueryByExample => DCQL', () => {
    it('should process deep query', async () => {
      const dcqlCredentialQuery = _fromQueryByExampleQuery({
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
      expect(dcqlCredentialQuery.id).to.exist;
      expect(dcqlCredentialQuery.format).to.eql('ldp_vc');
      expect(dcqlCredentialQuery.meta.type_values).to.deep.equal([
        'https://www.w3.org/2018/credentials#VerifiableCredential'
      ]);
      expect(dcqlCredentialQuery.claims).to.deep.equal([
        {
          path: ['@context', 0],
          values: ['https://www.w3.org/ns/credentials/v2']
        },
        {
          path: ['@context', 1],
          values: ['https://w3id.org/vital-records/v1rc4']
        },
        {
          path: ['type'],
          values: ['BirthCertificateCredential']},
        {
          path: ['credentialSubject', 'type'],
          values: ['BirthCertificate']
        },
        {
          path: ['credentialSubject', 'certifier' ]},
        {
          path: ['credentialSubject', 'newborn', 'name']},
        {
          path: ['credentialSubject', 'newborn', 'birthDate']},
        {
          path: ['credentialSubject', 'newborn', 'parent', 0, 'name'],
          values: ['John Doe']
        }
      ]);
    });
    it('should process deep query and nullyify indices', async () => {
      const dcqlCredentialQuery = _fromQueryByExampleQuery({
        nullyifyArrayIndices: true,
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
      expect(dcqlCredentialQuery.id).to.exist;
      expect(dcqlCredentialQuery.format).to.eql('ldp_vc');
      expect(dcqlCredentialQuery.meta.type_values).to.deep.equal([
        'https://www.w3.org/2018/credentials#VerifiableCredential'
      ]);
      expect(dcqlCredentialQuery.claims).to.deep.equal([
        {
          path: ['@context', 0],
          values: ['https://www.w3.org/ns/credentials/v2']
        },
        {
          path: ['@context', 1],
          values: ['https://w3id.org/vital-records/v1rc4']
        },
        {
          path: ['type'],
          values: ['BirthCertificateCredential']},
        {
          path: ['credentialSubject', 'type'],
          values: ['BirthCertificate']
        },
        {
          path: ['credentialSubject', 'certifier' ]},
        {
          path: ['credentialSubject', 'newborn', 'name']},
        {
          path: ['credentialSubject', 'newborn', 'birthDate']},
        {
          path: ['credentialSubject', 'newborn', 'parent', null, 'name'],
          values: ['John Doe']
        }
      ]);
    });
  });
});
