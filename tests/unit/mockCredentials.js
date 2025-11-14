/*!
 * Copyright (c) 2025 Digital Bazaar, Inc. All rights reserved.
 */

// credentials for comprehensive `QueryByExample` testing
export const mockCredentials = [
  // University Degree Credential - complex nested structure
  {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://www.w3.org/ns/credentials/examples/v2'
    ],
    id: 'http://example.edu/credentials/degree-001',
    type: ['VerifiableCredential', 'UniversityDegreeCredential'],
    credentialSubject: {
      id: 'did:example:123',
      name: 'John Doe',
      degree: {
        type: 'BachelorDegree',
        name: 'Bachelor of Science',
        major: 'Computer Science',
        gpa: 3.8
      },
      alumniOf: {
        name: 'University of Example',
        location: 'City, State',
        accreditation: ['ABET', 'Regional']
      },
      graduationDate: '2023-05-15T00:00:00Z'
    },
    issuer: {
      id: 'did:example:university',
      name: 'University of Example'
    },
    validFrom: '2023-01-01T00:00:00Z'
  },

  // Driver's License - array fields and null values
  {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://www.w3.org/ns/credentials/examples/v2'
    ],
    id: 'http://example.dmv/licenses/dl-456',
    type: ['VerifiableCredential', 'DriverLicense'],
    credentialSubject: {
      id: 'did:example:456',
      name: 'Jane Smith',
      licenseNumber: 'DL123456789',
      // array for testing
      licenseClass: ['A', 'B', 'C'],
      // null for testing null semantics
      restrictions: null,
      endorsements: ['Motorcycle', 'Commercial'],
      address: {
        street: '123 Main St',
        city: 'Anytown',
        state: 'CA',
        postalCode: '90210'
      }
    },
    issuer: {
      id: 'did:example:dmv',
      name: 'Department of Motor Vehicles'
    },
    validFrom: '2022-06-01T00:00:00Z',
    validUntil: '2027-06-01T00:00:00Z'
  },

  // Employee Credential - skills array and department info
  {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://www.w3.org/ns/credentials/examples/v2'
    ],
    id: 'http://example.company/employees/emp-789',
    type: ['VerifiableCredential', 'EmployeeCredential'],
    credentialSubject: {
      id: 'did:example:789',
      name: 'Bob Wilson',
      employeeId: 'EMP-789',
      department: 'Engineering',
      position: 'Senior Developer',
      // array for testing
      skills: ['JavaScript', 'Python', 'Go', 'Docker'],
      clearanceLevel: 'Secret',
      startDate: '2020-03-01T00:00:00Z',
      manager: {
        name: 'Alice Johnson',
        id: 'did:example:manager-001'
      }
    },
    issuer: {
      id: 'did:example:company',
      name: 'Example Corporation'
    },
    validFrom: '2020-03-01T00:00:00Z'
  },

  // Medical Credential - testing various data types
  {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://www.w3.org/ns/credentials/examples/v2'
    ],
    id: 'http://example.hospital/records/med-321',
    type: ['VerifiableCredential', 'MedicalCredential'],
    credentialSubject: {
      id: 'did:example:321',
      name: 'Carol Davis',
      bloodType: 'O+',
      // empty array for wildcard testing
      allergies: [],
      // null for testing
      medications: null,
      vaccinations: [
        {
          name: 'COVID-19',
          date: '2023-01-15T00:00:00Z',
          lot: 'ABC123'
        },
        {
          name: 'Influenza',
          date: '2022-10-01T00:00:00Z',
          lot: 'FLU456'
        }
      ],
      emergencyContact: {
        name: 'David Davis',
        relationship: 'Spouse',
        phone: '555-0123'
      }
    },
    issuer: {
      id: 'did:example:hospital',
      name: 'Example Hospital'
    },
    validFrom: '2023-02-01T00:00:00Z'
  },

  // Professional License - minimal structure for edge case testing
  {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://www.w3.org/ns/credentials/examples/v2'
    ],
    id: 'http://example.board/licenses/prof-555',
    type: ['VerifiableCredential', 'ProfessionalLicense'],
    credentialSubject: {
      id: 'did:example:555',
      name: 'Eve Martinez',
      licenseType: 'Nursing',
      licenseNumber: 'RN987654',
      status: 'Active',
      // array
      specializations: ['ICU', 'Emergency'],
      // null testing
      disciplinaryActions: null,
      // empty object for wildcard testing
      continuingEducation: {}
    },
    issuer: {
      id: 'did:example:nursing-board',
      name: 'State Nursing Board'
    },
    validFrom: '2021-01-01T00:00:00Z'
  }
];

// Test credentials for specific edge cases
export const edgeCaseCredentials = [
  // Credential with missing fields (for null testing)
  {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://www.w3.org/ns/credentials/examples/v2'
    ],
    type: ['VerifiableCredential'],
    credentialSubject: {
      id: 'did:example:minimal',
      name: 'Minimal Person'
      // intentionally missing many fields
    },
    issuer: {
      id: 'did:example:issuer'
    }
  },

  // Credential with string numbers (for type coercion testing)
  {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://www.w3.org/ns/credentials/examples/v2'
    ],
    type: ['VerifiableCredential', 'AgeCredential'],
    credentialSubject: {
      id: 'did:example:age-test',
      name: 'Age Test Person',
      // string number
      age: '25',
      // actual number
      yearOfBirth: 1998
    },
    issuer: {
      id: 'did:example:issuer'
    }
  },

  // Credential with whitespace issues (for string normalization testing)
  {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://www.w3.org/ns/credentials/examples/v2'
    ],
    type: ['VerifiableCredential'],
    credentialSubject: {
      id: 'did:example:whitespace',
      // extra spaces
      name: '  Whitespace Person  ',
      // Tabs and newlines
      title: '\tSenior Engineer\n'
    },
    issuer: {
      id: 'did:example:issuer'
    }
  },

  // Credential with array of arrays ... of arrays ... and arrays!
  {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://www.w3.org/ns/credentials/examples/v2'
    ],
    type: [
      'VerifiableCredential',
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
  },

  // a non-matching Credential with embedded arrays
  {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://www.w3.org/ns/credentials/examples/v2'
    ],
    type: [
      'VerifiableCredential',
      'ExampleDimensionsCredential'
    ],
    credentialSubject: {
      type: 'ExampleDimensions2',
      outer: [
        [{
          inner: [[0, 1], [2, 3]]
        }],
        [{
          inner: [[4, 5], [8, 8]]
        }]
      ]
    }
  }
];
