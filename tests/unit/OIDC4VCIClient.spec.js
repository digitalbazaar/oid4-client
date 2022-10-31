/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
import {OIDC4VCIClient} from '../../lib/index.js';

chai.should();
const {expect} = chai;

describe('OIDC4VCIClient', () => {
  describe('constructor', () => {
    it('should create an OIDC4VCIClient', async () => {
      const client = new OIDC4VCIClient({});
      expect(client).to.exist;
    });
  });
});
