/*!
 * Copyright (c) 2025 Digital Bazaar, Inc. All rights reserved.
 */
import {fromVpr, toVpr} from '../../lib/convert/index.js';
import chai from 'chai';

chai.should();
const {expect} = chai;

describe('convert', () => {
  describe('fromVpr()', () => {
    it('VPR => authorization request', async () => {
      const verifiablePresentationRequest = {
        query: [{
          type: 'QueryByExample',
          credentialQuery: {
            reason:
              `Please present your child's birth certificate to complete ` +
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
        }, {
          type: 'DIDAuthentication',
          acceptedMethods: [{method: 'key'}],
          acceptedCryptosuites: [{cryptosuite: 'ecdsa-rdfc-2019'}]
        }],
        domain: 'https://domain.example',
        challenge: '1234-challenge'
      };

      const authorizationRequest = fromVpr({
        verifiablePresentationRequest
      });
      expect(authorizationRequest).to.exist;
      expect(authorizationRequest).to.have.keys([
        'response_type', 'response_mode',
        'client_id', 'client_id_scheme',
        'response_uri', 'nonce', 'client_metadata',
        'dcql_query', 'presentation_definition'
      ]);

      const {
        response_type,
        response_mode,
        client_id,
        client_id_scheme,
        response_uri,
        nonce,
        client_metadata,
        dcql_query,
        presentation_definition
      } = authorizationRequest;

      expect(response_type).to.equal('vp_token');
      expect(response_mode).to.equal('direct_post');
      expect(client_id).to.equal(verifiablePresentationRequest.domain);
      expect(client_id_scheme).to.equal('redirect_uri');
      expect(response_uri).to.equal(verifiablePresentationRequest.domain);
      expect(nonce).to.equal(verifiablePresentationRequest.challenge);

      // OID4VP 1.0+
      const {vp_formats_supported} = client_metadata;
      expect(vp_formats_supported).to.exist;
      expect(vp_formats_supported).to.deep.equal({
        ldp_vc: {
          proof_type_values: ['DataIntegrityProof'],
          cryptosuite_values: ['ecdsa-rdfc-2019']
        }
      });

      // legacy (pre-OID4VP 1.0)
      const {vp_formats} = client_metadata;
      expect(vp_formats).to.exist;
      expect(vp_formats).to.deep.equal({
        ldp_vp: {
          proof_type: ['ecdsa-rdfc-2019']
        }
      });

      expect(dcql_query.credentials).to.exist;
      const {credentials} = dcql_query;
      expect(credentials.length).to.eql(1);
      const credentialQuery = credentials[0];
      expect(credentialQuery.format).to.eql('ldp_vc');
      expect(credentialQuery.meta.type_values).to.deep.equal([
        'https://www.w3.org/2018/credentials#VerifiableCredential'
      ]);
      expect(credentialQuery.claims).to.deep.equal([
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
      expect(dcql_query.credential_sets).to.exist;
      const {credential_sets} = dcql_query;
      expect(credential_sets?.[0].options?.[0]).to.be.an('array');
      expect(credential_sets?.[0].options?.[0]?.[0]).to.be.a('string');

      expect(presentation_definition.id).to.exist;
      expect(presentation_definition.input_descriptors).to.exist;
    });

    it('VPR w/groups => authorization request', async () => {
      const verifiablePresentationRequest = {
        query: [{
          type: 'QueryByExample',
          group: 'non-enveloped',
          credentialQuery: {
            reason:
              `Please present your child's birth certificate to complete ` +
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
            },
            acceptedCryptosuites: [{cryptosuite: 'ecdsa-rdfc-2019'}]
          }
        }, {
          type: 'DIDAuthentication',
          group: 'non-enveloped',
          acceptedMethods: [{method: 'key'}],
          acceptedCryptosuites: [{cryptosuite: 'ecdsa-rdfc-2019'}]
        }, {
          type: 'QueryByExample',
          group: 'enveloped',
          credentialQuery: {
            reason:
              `Please present your child's birth certificate to complete ` +
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
            },
            acceptedEnvelopes: ['application/jwt']
          }
        }, {
          type: 'DIDAuthentication',
          group: 'enveloped',
          acceptedMethods: [{method: 'key'}],
          acceptedEnvelopes: ['application/jwt']
        }],
        domain: 'https://domain.example',
        challenge: '1234-challenge'
      };

      const authorizationRequest = fromVpr({
        verifiablePresentationRequest
      });
      expect(authorizationRequest).to.exist;
      expect(authorizationRequest).to.have.keys([
        'response_type', 'response_mode',
        'client_id', 'client_id_scheme',
        'response_uri', 'nonce', 'client_metadata',
        'dcql_query', 'presentation_definition'
      ]);

      const {
        response_type,
        response_mode,
        client_id,
        client_id_scheme,
        response_uri,
        nonce,
        client_metadata,
        dcql_query,
        presentation_definition
      } = authorizationRequest;

      expect(response_type).to.equal('vp_token');
      expect(response_mode).to.equal('direct_post');
      expect(client_id).to.equal(verifiablePresentationRequest.domain);
      expect(client_id_scheme).to.equal('redirect_uri');
      expect(response_uri).to.equal(verifiablePresentationRequest.domain);
      expect(nonce).to.equal(verifiablePresentationRequest.challenge);

      // OID4VP 1.0+
      const {vp_formats_supported} = client_metadata;
      expect(vp_formats_supported).to.exist;
      expect(vp_formats_supported).to.deep.equal({
        ldp_vc: {
          proof_type_values: ['DataIntegrityProof'],
          cryptosuite_values: ['ecdsa-rdfc-2019']
        },
        jwt_vc_json: {},
        // legacy (pre-OID4VP 1.0)
        jwt_vp_json: {}
      });

      // legacy (pre-OID4VP 1.0)
      const {vp_formats} = client_metadata;
      expect(vp_formats).to.exist;
      expect(vp_formats).to.deep.equal({
        ldp_vp: {
          proof_type: ['ecdsa-rdfc-2019']
        }
      });

      expect(dcql_query.credentials).to.exist;
      const {credentials} = dcql_query;
      expect(credentials.length).to.eql(2);
      expect(credentials[0].format).to.eql('ldp_vc');
      expect(credentials[1].format).to.eql('jwt_vc_json');
      expect(credentials[0].meta.type_values).to.deep.equal([
        'https://www.w3.org/2018/credentials#VerifiableCredential'
      ]);
      expect(credentials[1].meta.type_values).to.deep.equal([
        'https://www.w3.org/2018/credentials#VerifiableCredential'
      ]);

      expect(dcql_query.credential_sets).to.exist;
      const {credential_sets} = dcql_query;
      credential_sets.length.should.equal(1);
      expect(credential_sets?.[0].options?.length).to.equal(2);
      expect(credential_sets[0].options[0]).to.be.an('array');
      expect(credential_sets[0].options[0][0]).to.equal(
        credentials[0].id);
      expect(credential_sets[0].options[1][0]).to.equal(
        credentials[1].id);

      expect(presentation_definition.id).to.exist;
      expect(presentation_definition.input_descriptors).to.exist;
    });

    it('VPR => authorization request w/client ID prefix', async () => {
      const verifiablePresentationRequest = {
        query: [{
          type: 'QueryByExample',
          credentialQuery: {
            reason:
              `Please present your child's birth certificate to complete ` +
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
        }, {
          type: 'DIDAuthentication',
          acceptedMethods: [{method: 'key'}],
          acceptedCryptosuites: [{cryptosuite: 'ecdsa-rdfc-2019'}]
        }],
        domain: 'https://domain.example',
        challenge: '1234-challenge'
      };

      const authorizationRequest = fromVpr({
        verifiablePresentationRequest,
        useClientIdPrefix: true
      });
      expect(authorizationRequest).to.exist;
      expect(authorizationRequest).to.have.keys([
        'response_type', 'response_mode',
        'client_id',
        'response_uri', 'nonce', 'client_metadata',
        'dcql_query', 'presentation_definition'
      ]);

      const {
        response_type,
        response_mode,
        client_id,
        response_uri,
        nonce,
        client_metadata,
        dcql_query,
        presentation_definition
      } = authorizationRequest;

      expect(response_type).to.equal('vp_token');
      expect(response_mode).to.equal('direct_post');
      expect(client_id).to.equal(
        `redirect_uri:${verifiablePresentationRequest.domain}`);
      expect(response_uri).to.equal(verifiablePresentationRequest.domain);
      expect(nonce).to.equal(verifiablePresentationRequest.challenge);
      expect(client_metadata).to.exist;

      expect(dcql_query.credentials).to.exist;
      expect(dcql_query.credential_sets).to.exist;
      const {credentials} = dcql_query;
      expect(credentials.length).to.eql(1);
      const credentialQuery = credentials[0];
      expect(credentialQuery.format).to.eql('ldp_vc');
      expect(credentialQuery.meta.type_values).to.deep.equal([
        'https://www.w3.org/2018/credentials#VerifiableCredential'
      ]);

      expect(presentation_definition.id).to.exist;
      expect(presentation_definition.input_descriptors).to.exist;
    });
  });

  describe('toVpr()', () => {
    it('authorization request => VPR', async () => {
      const purpose =
        `Please present your child's birth certificate to complete ` +
        'the verification process.';
      const authorizationRequest = {
        response_type: 'vp_token',
        response_mode: 'direct_post',
        client_id: 'redirect_uri:https://domain.example',
        response_uri: 'https://domain.example',
        nonce: '1234-challenge',
        client_metadata: {
          require_signed_request_object: false,
          vp_formats: {
            ldp_vp: {
              proof_type: ['ecdsa-rdfc-2019']
            }
          },
          vp_formats_supported: {
            ldp_vc: {
              proof_type_values: ['DataIntegrityProof'],
              cryptosuite_values: ['ecdsa-rdfc-2019']
            }
          }
        },
        dcql_query: {
          credentials: [{
            id: '0acc5d1a-1fb0-4daf-b63a-832483b0497e',
            format: 'ldp_vc',
            meta: {
              reason: purpose,
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
          }],
          credential_sets: [{
            options: [
              ['0acc5d1a-1fb0-4daf-b63a-832483b0497e']
            ]
          }]
        },
        presentation_definition: {
          id: '54cc4030-16c2-4d73-8d2f-a3b82e3a26ef',
          input_descriptors: [{
            id: '2a9c320e-9aa4-4df1-975b-cb773e170ad9',
            purpose,
            constraints: {
              fields: [{
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
              }]
            }
          }]
        }
      };

      const {verifiablePresentationRequest: vpr} = toVpr({
        authorizationRequest
      });

      // get group ID from VPR
      const groupId = vpr?.query?.[0]?.group;

      const expectedVpr = {
        query: [{
          type: 'QueryByExample',
          group: groupId,
          credentialQuery: {
            reason:
              `Please present your child's birth certificate to complete ` +
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
          }
        }, {
          type: 'DIDAuthentication',
          group: groupId,
          acceptedCryptosuites: [{cryptosuite: 'ecdsa-rdfc-2019'}]
        }],
        domain: 'https://domain.example',
        challenge: '1234-challenge'
      };

      expect(vpr).to.deep.equal(expectedVpr);
    });

    it('authorization request => VPR w/accepted envelopes', async () => {
      const purpose =
        `Please present your child's birth certificate to complete ` +
        'the verification process.';
      const authorizationRequest = {
        response_type: 'vp_token',
        response_mode: 'direct_post',
        client_id: 'redirect_uri:https://domain.example',
        response_uri: 'https://domain.example',
        nonce: '1234-challenge',
        client_metadata: {
          require_signed_request_object: false,
          vp_formats: {
            ldp_vp: {
              proof_type: ['ecdsa-rdfc-2019']
            }
          },
          vp_formats_supported: {
            ldp_vc: {
              proof_type_values: ['DataIntegrityProof'],
              cryptosuite_values: ['ecdsa-rdfc-2019']
            },
            jwt_vc_json: {}
          }
        },
        dcql_query: {
          credentials: [{
            id: '0acc5d1a-1fb0-4daf-b63a-832483b0497e',
            format: 'ldp_vc',
            meta: {
              reason: purpose,
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
          }],
          credential_sets: [{
            options: [
              ['0acc5d1a-1fb0-4daf-b63a-832483b0497e']
            ]
          }]
        }
      };

      const {verifiablePresentationRequest: vpr} = toVpr({
        authorizationRequest
      });

      // get group ID from VPR
      const groupId = vpr?.query?.[0]?.group;

      const expectedVpr = {
        query: [{
          type: 'QueryByExample',
          group: groupId,
          credentialQuery: {
            reason:
              `Please present your child's birth certificate to complete ` +
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
          }
        }, {
          type: 'DIDAuthentication',
          group: groupId,
          acceptedCryptosuites: [{cryptosuite: 'ecdsa-rdfc-2019'}],
          acceptedEnvelopes: ['application/jwt']
        }],
        domain: 'https://domain.example',
        challenge: '1234-challenge'
      };

      expect(vpr).to.deep.equal(expectedVpr);
    });

    it('authorization request w/credential sets => VPR', async () => {
      const purpose =
        `Please present your child's birth certificate to complete ` +
        'the verification process.';
      const authorizationRequest = {
        response_type: 'vp_token',
        response_mode: 'direct_post',
        client_id: 'redirect_uri:https://domain.example',
        response_uri: 'https://domain.example',
        nonce: '1234-challenge',
        client_metadata: {
          require_signed_request_object: false,
          vp_formats: {
            ldp_vp: {
              proof_type: ['ecdsa-rdfc-2019']
            }
          },
          vp_formats_supported: {
            ldp_vc: {
              proof_type_values: ['DataIntegrityProof'],
              cryptosuite_values: ['ecdsa-rdfc-2019']
            },
            jwt_vc_json: {}
          }
        },
        dcql_query: {
          credentials: [{
            id: '0acc5d1a-1fb0-4daf-b63a-832483b0497e',
            format: 'ldp_vc',
            meta: {
              reason: purpose,
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
          }, {
            id: 'f00070d6-2edb-44ae-8f57-f35557fe76bc',
            format: 'jwt_vc_json',
            meta: {
              reason: purpose,
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
          }],
          credential_sets: [{
            options: [
              ['0acc5d1a-1fb0-4daf-b63a-832483b0497e'],
              ['f00070d6-2edb-44ae-8f57-f35557fe76bc']
            ]
          }]
        }
      };

      const {verifiablePresentationRequest: vpr} = toVpr({
        authorizationRequest
      });

      // get group IDs from VPR
      const groupIds = [...new Set(vpr.query.map(({group}) => group))];
      const [groupId1, groupId2] = groupIds;

      const expectedVpr = {
        query: [{
          type: 'QueryByExample',
          group: groupId1,
          credentialQuery: {
            reason:
              `Please present your child's birth certificate to complete ` +
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
          }
        }, {
          type: 'QueryByExample',
          group: groupId2,
          credentialQuery: {
            reason:
              `Please present your child's birth certificate to complete ` +
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
          }
        }, {
          type: 'DIDAuthentication',
          group: groupId1,
          acceptedCryptosuites: [{cryptosuite: 'ecdsa-rdfc-2019'}],
          acceptedEnvelopes: ['application/jwt']
        }, {
          type: 'DIDAuthentication',
          group: groupId2,
          acceptedCryptosuites: [{cryptosuite: 'ecdsa-rdfc-2019'}],
          acceptedEnvelopes: ['application/jwt']
        }],
        domain: 'https://domain.example',
        challenge: '1234-challenge'
      };

      expect(vpr).to.deep.equal(expectedVpr);
    });

    it('authorization request => VPR (PE only)', async () => {
      const purpose =
        `Please present your child's birth certificate to complete ` +
        'the verification process.';
      const authorizationRequest = {
        response_type: 'vp_token',
        response_mode: 'direct_post',
        client_id: 'redirect_uri:https://domain.example',
        response_uri: 'https://domain.example',
        nonce: '1234-challenge',
        client_metadata: {
          require_signed_request_object: false,
          vp_formats: {
            ldp_vp: {
              proof_type: ['ecdsa-rdfc-2019']
            }
          },
          vp_formats_supported: {
            ldp_vc: {
              proof_type_values: ['DataIntegrityProof'],
              cryptosuite_values: ['ecdsa-rdfc-2019']
            }
          }
        },
        presentation_definition: {
          id: '54cc4030-16c2-4d73-8d2f-a3b82e3a26ef',
          input_descriptors: [{
            id: '2a9c320e-9aa4-4df1-975b-cb773e170ad9',
            purpose,
            constraints: {
              fields: [{
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
              }]
            }
          }]
        }
      };

      const {verifiablePresentationRequest: vpr} = toVpr({
        authorizationRequest
      });

      const expectedVpr = {
        query: [{
          type: 'QueryByExample',
          credentialQuery: {
            reason:
              `Please present your child's birth certificate to complete ` +
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
                  parent: [{}]
                }
              }
            }
          }
        }, {
          type: 'DIDAuthentication',
          acceptedCryptosuites: [{cryptosuite: 'ecdsa-rdfc-2019'}]
        }],
        domain: 'https://domain.example',
        challenge: '1234-challenge'
      };

      expect(vpr).to.deep.equal(expectedVpr);
    });
  });
});
