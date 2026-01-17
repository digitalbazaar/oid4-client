/*!
 * Copyright (c) 2025-2026 Digital Bazaar, Inc. All rights reserved.
 */
import {
  _fromQueryByExampleQuery, _toQueryByExampleQuery
} from '../../lib/query/dcql.js';
import chai from 'chai';

chai.should();
const {expect} = chai;

describe('query.dcql', () => {
  describe('QueryByExample => DCQL', () => {
    it('should handle "acceptedEnvelopes"', async () => {
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
              type: 'BirthCertificate'
            }
          },
          acceptedEnvelopes: ['application/jwt']
        }
      });
      expect(dcqlCredentialQuery.id).to.exist;
      expect(dcqlCredentialQuery.format).to.eql('jwt_vc_json');
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
          path: ['type', null],
          values: ['BirthCertificateCredential']},
        {
          path: ['credentialSubject', 'type'],
          values: ['BirthCertificate']
        }
      ]);
    });
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
          path: ['type', null],
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
          path: ['type', null],
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
  it('should process array of arrays query', async () => {
    const dcqlCredentialQuery = _fromQueryByExampleQuery({
      credentialQuery: {
        reason: 'Present your geolocation credential to claim the prize.',
        example: {
          '@context': [
            'https://www.w3.org/ns/credentials/v2',
            'https://www.w3.org/ns/credentials/examples/v2'
          ],
          type: [
            'ExampleGeoLocationCredential'
          ],
          credentialSubject: {
            type: 'ExampleGeoLocation',
            location: [[0, 1], [2, 3]]
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
        values: ['https://www.w3.org/ns/credentials/examples/v2']
      },
      {
        path: ['type', null],
        values: ['ExampleGeoLocationCredential']},
      {
        path: ['credentialSubject', 'type'],
        values: ['ExampleGeoLocation']
      },
      {
        path: ['credentialSubject', 'location', 0, 0],
        values: [0]
      },
      {
        path: ['credentialSubject', 'location', 0, 1],
        values: [1]
      },
      {
        path: ['credentialSubject', 'location', 1, 0],
        values: [2]
      },
      {
        path: ['credentialSubject', 'location', 1, 1],
        values: [3]
      }
    ]);
  });
  it('should process array of arrays of arrays query', async () => {
    const dcqlCredentialQuery = _fromQueryByExampleQuery({
      credentialQuery: {
        reason: 'Present your tensor credential to claim the prize.',
        example: {
          '@context': [
            'https://www.w3.org/ns/credentials/v2',
            'https://www.w3.org/ns/credentials/examples/v2'
          ],
          type: [
            'ExampleTensorCredential'
          ],
          credentialSubject: {
            type: 'ExampleTensor',
            tensor: [[[0, 1], [2, 3]], [[4, 5], [6, 7]]]
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
        values: ['https://www.w3.org/ns/credentials/examples/v2']
      },
      {
        path: ['type', null],
        values: ['ExampleTensorCredential']},
      {
        path: ['credentialSubject', 'type'],
        values: ['ExampleTensor']
      },
      {
        path: ['credentialSubject', 'tensor', 0, 0, 0],
        values: [0]
      },
      {
        path: ['credentialSubject', 'tensor', 0, 0, 1],
        values: [1]
      },
      {
        path: ['credentialSubject', 'tensor', 0, 1, 0],
        values: [2]
      },
      {
        path: ['credentialSubject', 'tensor', 0, 1, 1],
        values: [3]
      },
      {
        path: ['credentialSubject', 'tensor', 1, 0, 0],
        values: [4]
      },
      {
        path: ['credentialSubject', 'tensor', 1, 0, 1],
        values: [5]
      },
      {
        path: ['credentialSubject', 'tensor', 1, 1, 0],
        values: [6]
      },
      {
        path: ['credentialSubject', 'tensor', 1, 1, 1],
        values: [7]
      }
    ]);
  });
  it('should process array of arrays inside objects query', async () => {
    const dcqlCredentialQuery = _fromQueryByExampleQuery({
      credentialQuery: {
        reason: 'Present your dimensions credential to claim the prize.',
        example: {
          '@context': [
            'https://www.w3.org/ns/credentials/v2',
            'https://www.w3.org/ns/credentials/examples/v2'
          ],
          type: [
            'ExampleDimensionsCredential'
          ],
          credentialSubject: {
            type: 'ExampleDimensions',
            outer: [
              [{
                inner: [[0, 1], [2, 3]]
              }],
              [{
                inner: [[4, 5], [6, 7]]
              }]
            ]
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
        values: ['https://www.w3.org/ns/credentials/examples/v2']
      },
      {
        path: ['type', null],
        values: ['ExampleDimensionsCredential']},
      {
        path: ['credentialSubject', 'type'],
        values: ['ExampleDimensions']
      },
      {
        path: ['credentialSubject', 'outer', 0, 0, 'inner', 0, 0],
        values: [0]
      },
      {
        path: ['credentialSubject', 'outer', 0, 0, 'inner', 0, 1],
        values: [1]
      },
      {
        path: ['credentialSubject', 'outer', 0, 0, 'inner', 1, 0],
        values: [2]
      },
      {
        path: ['credentialSubject', 'outer', 0, 0, 'inner', 1, 1],
        values: [3]
      },
      {
        path: ['credentialSubject', 'outer', 1, 0, 'inner', 0, 0],
        values: [4]
      },
      {
        path: ['credentialSubject', 'outer', 1, 0, 'inner', 0, 1],
        values: [5]
      },
      {
        path: ['credentialSubject', 'outer', 1, 0, 'inner', 1, 0],
        values: [6]
      },
      {
        path: ['credentialSubject', 'outer', 1, 0, 'inner', 1, 1],
        values: [7]
      }
    ]);
  });

  describe('DCQL => QueryByExample', () => {
    it('should handle "acceptedEnvelopes"', async () => {
      const credentialQuery = _toQueryByExampleQuery({
        dcqlCredentialQuery: {
          id: crypto.randomUUID(),
          format: 'jwt_vc_json',
          meta: {
            reason:
            `Please present your child's birth certificate to complete ` +
              'the verification process.',
            type_values: [
              'https://www.w3.org/2018/credentials#VerifiableCredential'
            ]
          },
          claims: [
            {
              path: ['@context', 0],
              values: ['https://www.w3.org/ns/credentials/v2']
            },
            {
              path: ['@context', 1],
              values: ['https://w3id.org/vital-records/v1rc4']
            },
            {
              path: ['type', null],
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
          ]
        }
      });

      const expectedCredentialQuery = {
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
            certifier: '',
            newborn: {
              name: '',
              birthDate: '',
              parent: [{
                name: 'John Doe'
              }]
            }
          }
        },
        acceptedEnvelopes: ['application/jwt']
      };

      expect(credentialQuery).to.deep.equal(expectedCredentialQuery);
    });
    it('should process deep query', async () => {
      const credentialQuery = _toQueryByExampleQuery({
        dcqlCredentialQuery: {
          id: crypto.randomUUID(),
          format: 'ldp_vc',
          meta: {
            reason:
            `Please present your child's birth certificate to complete ` +
              'the verification process.',
            type_values: [
              'https://www.w3.org/2018/credentials#VerifiableCredential'
            ]
          },
          claims: [
            {
              path: ['@context', 0],
              values: ['https://www.w3.org/ns/credentials/v2']
            },
            {
              path: ['@context', 1],
              values: ['https://w3id.org/vital-records/v1rc4']
            },
            {
              path: ['type', null],
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
          ]
        }
      });

      const expectedCredentialQuery = {
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
            certifier: '',
            newborn: {
              name: '',
              birthDate: '',
              parent: [{
                name: 'John Doe'
              }]
            }
          }
        }
      };

      expect(credentialQuery).to.deep.equal(expectedCredentialQuery);
    });
  });
});
