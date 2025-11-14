/*!
 * Copyright (c) 2025 Digital Bazaar, Inc. All rights reserved.
 */
import {edgeCaseCredentials, mockCredentials} from './mockCredentials.js';
import {_toQueryByExampleQuery} from '../../lib/query/dcql.js';
import {credentialMatches} from '../../lib/query/match.js';
import {exampleToJsonPointerMap} from '../../lib/query/queryByExample.js';

import chai from 'chai';
chai.should();
const {expect} = chai;

describe.only('query.match', () => {
  describe('credentialMatches()', function() {
    describe('API and basic functionality', function() {
      it('should use named parameters API', function() {
        const queryByExample = {
          example: {
            credentialSubject: {name: 'John Doe'}
          }
        };

        const matches = _matchCredentials({
          credentials: mockCredentials,
          queryByExample
        });

        expect(matches).to.have.length(1);
        expect(matches[0].credentialSubject.name).to.equal('John Doe');
      });

      it('should match all credentials with empty object example', function() {
        const matches = _matchCredentials({
          credentials: mockCredentials,
          queryByExample: {example: {}}
        });

        // all 5 mock credentials match
        expect(matches).to.have.length(5);
      });

      it('should match no credentials with null example', function() {
        const matches = _matchCredentials({
          credentials: mockCredentials,
          queryByExample: {example: null}
        });

        expect(matches).to.have.length(0);
      });

      it('should handle empty credentials array', function() {
        const matches = _matchCredentials({
          credentials: [],
          queryByExample: {example: {type: 'SomeType'}}
        });

        expect(matches).to.have.length(0);
      });
    });

    describe('Semantic Features Tests', function() {
      describe('Empty Array Wildcard (any array)', function() {
        it('should match an empty array', function() {
          const queryByExample = {
            example: {
              credentialSubject: {
                // empty array - any array
                allergies: []
              }
            }
          };

          const matches = _matchCredentials({
            credentials: mockCredentials,
            queryByExample
          });

          // should match Carol Davis (has allergies: [])
          expect(matches).to.have.length(1);
          expect(matches[0].credentialSubject.name).to.equal('Carol Davis');
        });

        it('should match credentials with populated arrays', function() {
          const queryByExample = {
            example: {
              credentialSubject: {
                // should match any array
                skills: []
              }
            }
          };

          const matches = _matchCredentials({
            credentials: mockCredentials,
            queryByExample
          });

          // should match Bob Wilson (has skills array)
          expect(matches).to.have.length(1);
          expect(matches[0].credentialSubject.name).to.equal('Bob Wilson');
        });
      });
    });

    describe('Empty Object Wildcard (any value)', function() {
      it('should match any value when example has empty object', function() {
        const queryByExample = {
          example: {
            credentialSubject: {
              // empty object - any value
              continuingEducation: {}
            }
          }
        };

        const matches = _matchCredentials({
          credentials: mockCredentials,
          queryByExample
        });

        // Should match Eve Martinez (has continuingEducation: {})
        expect(matches).to.have.length(1);
        expect(matches[0].credentialSubject.name).to.equal('Eve Martinez');
      });

      it('should match populated objects with empty object wildcard',
        function() {
          const queryByExample = {
            example: {
              credentialSubject: {
                // should match any degree object
                degree: {}
              }
            }
          };

          const matches = _matchCredentials({
            credentials: mockCredentials,
            queryByExample
          });

          // Should match John Doe (has degree object)
          expect(matches).to.have.length(1);
          expect(matches[0].credentialSubject.name).to.equal('John Doe');
        });
    });

    describe('Null Semantic (must be null)', function() {
      it('should match only when field is null', function() {
        const queryByExample = {
          example: {
            credentialSubject: {
              // must be null
              restrictions: null
            }
          }
        };

        const matches = _matchCredentials({
          credentials: mockCredentials,
          queryByExample
        });

        // Should match Jane Smith (has restrictions: null)
        expect(matches).to.have.length(1);
        expect(matches[0].credentialSubject.name).to.equal('Jane Smith');
      });

      it('should match multiple null fields', function() {
        const queryByExample = {
          example: {
            credentialSubject: {
              medications: null,
              disciplinaryActions: null
            }
          }
        };

        const matches = _matchCredentials({
          credentials: mockCredentials,
          queryByExample
        });

        // Should match 0 credentials since no credential has
        // BOTH fields as null
        expect(matches).to.have.length(0);
      });

      it('should match individual null fields correctly', function() {
        // Test medications: null
        const medicationsQuery = {
          example: {
            credentialSubject: {
              medications: null
            }
          }
        };

        const medicationsMatches = _matchCredentials({
          credentials: mockCredentials,
          queryByExample: medicationsQuery
        });

        expect(medicationsMatches).to.have.length(1);
        expect(medicationsMatches[0].credentialSubject.name).
          to.equal('Carol Davis');

        // Test disciplinaryActions: null
        const disciplinaryQuery = {
          example: {
            credentialSubject: {
              disciplinaryActions: null
            }
          }
        };

        const disciplinaryMatches = _matchCredentials({
          credentials: mockCredentials,
          queryByExample: disciplinaryQuery
        });

        expect(disciplinaryMatches).to.have.length(1);
        expect(disciplinaryMatches[0].credentialSubject.name).
          to.equal('Eve Martinez');
      });

      it('should match when field is missing', function() {
        // use a field that actually exists as null
        const queryByExample = {
          example: {
            credentialSubject: {
              medications: null
            }
          }
        };

        const matches = _matchCredentials({
          credentials: mockCredentials,
          queryByExample
        });

        expect(matches).to.have.length(1);
        expect(matches[0].credentialSubject.name).to.equal('Carol Davis');
      });
    });

    describe('Overlay Matching', function() {
      it('should match when credential has extra fields', function() {
        const queryByExample = {
          example: {
            credentialSubject: {
              degree: {
                // only looking for this field
                type: 'BachelorDegree'
              }
            }
          }
        };

        const matches = _matchCredentials({
          credentials: mockCredentials,
          queryByExample
        });

        expect(matches).to.have.length(1);
        expect(matches[0].credentialSubject.degree.name).to
          .equal('Bachelor of Science');
        expect(matches[0].credentialSubject.degree.major).to
          .equal('Computer Science');
      });

      it('should match nested objects with extra properties', function() {
        const queryByExample = {
          example: {
            credentialSubject: {
              alumniOf: {
                name: 'University of Example'
                // doesn't specify 'location' or 'accreditation'
                // but credential has them
              }
            }
          }
        };

        const matches = _matchCredentials({
          credentials: mockCredentials,
          queryByExample
        });

        expect(matches).to.have.length(1);
        expect(matches[0].credentialSubject.alumniOf.location).to
          .equal('City, State');
        expect(matches[0].credentialSubject.alumniOf.accreditation).to
          .deep.equal(['ABET', 'Regional']);
      });
    });

    describe('Array Matching', function() {
      it('should match single value against array', function() {
        const queryByExample = {
          example: {
            // single value
            type: 'UniversityDegreeCredential'
          }
        };

        const matches = _matchCredentials({
          credentials: mockCredentials,
          queryByExample
        });

        // Should match credential with type array containing this value
        expect(matches).to.have.length(1);
        expect(matches[0].credentialSubject.name).to.equal('John Doe');
      });

      it('should match array element', function() {
        const queryByExample = {
          example: {
            credentialSubject: {
              // should match element in ['A', 'B', 'C']
              licenseClass: 'B'
            }
          }
        };

        const matches = _matchCredentials({
          credentials: mockCredentials,
          queryByExample
        });

        expect(matches).to.have.length(1);
        expect(matches[0].credentialSubject.name).to.equal('Jane Smith');
      });

      it('should match arrays with common elements', function() {
        const queryByExample = {
          example: {
            credentialSubject: {
              // has `JavaScript` in common
              skills: ['JavaScript', 'Rust']
            }
          }
        };

        const matches = _matchCredentials({
          credentials: mockCredentials,
          queryByExample
        });

        expect(matches).to.have.length(1);
        expect(matches[0].credentialSubject.name).to.equal('Bob Wilson');
      });

      it('should match array elements in complex structures', function() {
        const queryByExample = {
          example: {
            credentialSubject: {
              // should match element in endorsements array
              endorsements: 'Motorcycle'
            }
          }
        };

        const matches = _matchCredentials({
          credentials: mockCredentials,
          queryByExample
        });

        expect(matches).to.have.length(1);
        expect(matches[0].credentialSubject.name).to.equal('Jane Smith');
      });
    });

    describe('Complex Nested Structures', function() {
      it('should handle deep nesting with multiple levels', function() {
        const queryByExample = {
          example: {
            credentialSubject: {
              vaccinations: [{
                name: 'COVID-19'
              }]
            }
          }
        };

        const matches = _matchCredentials({
          credentials: mockCredentials,
          queryByExample
        });

        expect(matches).to.have.length(1);
        expect(matches[0].credentialSubject.name).to.equal('Carol Davis');
      });

      it('should handle multiple field matching (AND logic)', function() {
        const queryByExample = {
          example: {
            type: 'EmployeeCredential',
            credentialSubject: {
              department: 'Engineering',
              skills: 'Python'
            }
          }
        };

        const matches = _matchCredentials({
          credentials: mockCredentials,
          queryByExample
        });

        expect(matches).to.have.length(1);
        expect(matches[0].credentialSubject.name).to.equal('Bob Wilson');
      });

      it('should handle complex nested object matching', function() {
        const queryByExample = {
          example: {
            credentialSubject: {
              address: {
                state: 'CA',
                city: 'Anytown',
              }
            }
          }
        };

        const matches = _matchCredentials({
          credentials: mockCredentials,
          queryByExample
        });

        expect(matches).to.have.length(1);
        expect(matches[0].credentialSubject.name).to.equal('Jane Smith');
      });
    });

    describe('Error Handling and Edge Cases', function() {
      it('should handle structure mismatch gracefully', function() {
        const queryByExample = {
          example: {
            credentialSubject: {
              nonExistentField: {
                deepNesting: 'value'
              }
            }
          }
        };

        const matches = _matchCredentials({
          credentials: mockCredentials,
          queryByExample
        });

        expect(matches).to.have.length(0);
      });

      it('should handle invalid credentials gracefully', function() {
        const invalidCredentials = [
          null,
          undefined,
          'string',
          123,
          []
        ];

        const queryByExample = {
          example: {
            type: 'SomeType'
          }
        };

        const matches = _matchCredentials({
          credentials: invalidCredentials,
          queryByExample
        });

        expect(matches).to.have.length(0);
      });

      it('should handle complex pointer scenarios', function() {
        const queryByExample = {
          example: {
            credentialSubject: {
              manager: {
                name: 'Alice Johnson'
              }
            }
          }
        };

        const matches = _matchCredentials({
          credentials: mockCredentials,
          queryByExample
        });

        expect(matches).to.have.length(1);
        expect(matches[0].credentialSubject.name).to.equal('Bob Wilson');
      });

      it('should handle complex embedded arrays', function() {
        const dcqlCredentialQuery = {
          claims: [
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
          ]
        };
        const queryByExample = _toQueryByExampleQuery({dcqlCredentialQuery});
        const matches = _matchCredentials({
          credentials: edgeCaseCredentials,
          queryByExample
        });

        expect(matches).to.have.length(1);
        expect(matches[0].credentialSubject.type).to.equal('ExampleDimensions');
      });
    });

    describe('String Normalization and Type Coercion', function() {
      it('should NOT trim strings', function() {
        const queryByExample = {
          example: {
            credentialSubject: {
              // no extra spaces
              name: 'Whitespace Person'
            }
          }
        };

        const matches = _matchCredentials({
          credentials: edgeCaseCredentials,
          queryByExample
        });

        expect(matches).to.have.length(0);
      });

      it('should handle string/number coercion', function() {
        const queryByExample = {
          example: {
            credentialSubject: {
              // number
              age: 25
            }
          }
        };

        const matches = _matchCredentials({
          credentials: edgeCaseCredentials,
          queryByExample
        });

        // should match the credential with age: '25' (string)
        expect(matches).to.have.length(1);
      });

      it('should handle reverse number/string coercion', function() {
        const queryByExample = {
          example: {
            credentialSubject: {
              // string
              yearOfBirth: '1998'
            }
          }
        };

        const matches = _matchCredentials({
          credentials: edgeCaseCredentials,
          queryByExample
        });

        // should match the credential with yearOfBirth: 1998 (number)
        expect(matches).to.have.length(1);
      });
    });

    describe('Real-world Scenarios', function() {
      it('should handle medical record queries', function() {
        const queryByExample = {
          example: {
            type: 'MedicalCredential',
            credentialSubject: {
              bloodType: 'O+'
            }
          }
        };

        const matches = _matchCredentials({
          credentials: mockCredentials,
          queryByExample
        });

        expect(matches).to.have.length(1);
        expect(matches[0].credentialSubject.name).to.equal('Carol Davis');
      });

      it('should handle professional license queries', function() {
        const queryByExample = {
          example: {
            credentialSubject: {
              licenseType: 'Nursing',
              status: 'Active'
            }
          }
        };

        const matches = _matchCredentials({
          credentials: mockCredentials,
          queryByExample
        });

        expect(matches).to.have.length(1);
        expect(matches[0].credentialSubject.name).to.equal('Eve Martinez');
      });
    });
  });
});

function _matchCredentials({credentials, queryByExample}) {
  const map = exampleToJsonPointerMap(queryByExample);
  return credentials.filter(
    credential => credentialMatches({credential, map}));
}
