/*!
 * Copyright (c) 2025 Digital Bazaar, Inc. All rights reserved.
 */
import {
  _fromQueryByExampleQuery
} from '../../lib/convert/dcql.js';
import chai from 'chai';

chai.should();
const {expect} = chai;

describe('convert.dcql', () => {
  describe('QueryByExample => DCQL', () => {
    it('should pass', async () => {
      const result = _fromQueryByExampleQuery({});
      expect(result).to.exist;
    });
  });
});
