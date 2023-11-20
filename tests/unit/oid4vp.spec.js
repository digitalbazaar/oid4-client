/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import {_fromQueryByExampleQuery} from '../../lib/oid4vp.js';
import chai from 'chai';

chai.should();
const {expect} = chai;

describe('OID4VP', () => {
  describe('constructor', () => {
    it('should map a QueryByExample to a Presentation Definition', async () => {
      const presentation_definition = _fromQueryByExampleQuery({
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
