const path = require('path');
const fs = require('fs');
const binding = require('bcrypt');
const bcrypt = require('../index.js');

describe('bcrypt', () => {
  describe('base64', () => {
    test('encodeBase64 should encode correctly', () => {
      const str = bcrypt.encodeBase64([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10], 16);
      expect(str).toBe("..CA.uOD/eaGAOmJB.yMBu");
    });

    test('decodeBase64 should decode correctly', () => {
      const bytes = bcrypt.decodeBase64("..CA.uOD/eaGAOmJB.yMBv.", 16);
      expect(bytes).toEqual([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
    });

    test('should handle invalid input', () => {
      // Should throw on invalid length
      expect(() => bcrypt.encodeBase64([], -1)).toThrow(/Illegal len/);
      expect(() => bcrypt.encodeBase64([], 1)).toThrow(/Illegal len/);
      expect(() => bcrypt.encodeBase64([], 0)).toThrow(/Illegal len/);
      
      // Should throw on length > array length
      expect(() => bcrypt.encodeBase64([1, 2], 3)).toThrow(/Illegal len/);
    });
  });

  describe('salt generation', () => {
    test('genSaltSync should generate valid salt', () => {
      const salt = bcrypt.genSaltSync(10);
      expect(salt).toBeTruthy();
      expect(typeof salt).toBe('string');
      expect(salt.length).toBeGreaterThan(0);
    });

    test('genSalt should generate valid salt asynchronously', async () => {
      const salt = await bcrypt.genSalt(10);
      expect(salt).toBeTruthy();
      expect(typeof salt).toBe('string');
      expect(salt.length).toBeGreaterThan(0);
    });
  });

  describe('hashing', () => {
    test('hashSync should generate different hashes for same input', () => {
      const hash1 = bcrypt.hashSync("hello", 10);
      const hash2 = bcrypt.hashSync("hello", 10);
      expect(hash1).not.toBe(hash2);
    });

    test('hash should work asynchronously', async () => {
      const hash = await bcrypt.hash("hello", 10);
      expect(hash).toBeTruthy();
    });
  });

  describe('comparison', () => {
    test('compareSync should work with different hash versions', () => {
      const salt1 = bcrypt.genSaltSync();
      const hash1 = bcrypt.hashSync("hello", salt1); // $2a$
      const salt2 = bcrypt.genSaltSync().replace(/\$2a\$/, "$2y$");
      const hash2 = bcrypt.hashSync("world", salt2);
      const salt3 = bcrypt.genSaltSync().replace(/\$2a\$/, "$2b$");
      const hash3 = bcrypt.hashSync("hello world", salt3);

      expect(hash1.substring(0,4)).toBe("$2a$");
      expect(bcrypt.compareSync("hello", hash1)).toBe(true);
      expect(bcrypt.compareSync("hello", hash2)).toBe(false);
      expect(bcrypt.compareSync("hello", hash3)).toBe(false);

      expect(hash2.substring(0,4)).toBe("$2y$");
      expect(bcrypt.compareSync("world", hash2)).toBe(true);
      expect(bcrypt.compareSync("world", hash1)).toBe(false);
      expect(bcrypt.compareSync("world", hash3)).toBe(false);

      expect(hash3.substring(0,4)).toBe("$2b$");
      expect(bcrypt.compareSync("hello world", hash3)).toBe(true);
      expect(bcrypt.compareSync("hello world", hash1)).toBe(false);
      expect(bcrypt.compareSync("hello world", hash2)).toBe(false);
    });

    test('should handle different bcrypt versions', () => {
      // Test $2y$ version
      const salt2y = bcrypt.genSaltSync().replace(/\$2a\$/, "$2y$");
      const hash2y = bcrypt.hashSync("world", salt2y);
      expect(hash2y.substring(0,4)).toBe("$2y$");
      expect(bcrypt.compareSync("world", hash2y)).toBe(true);

      // Test $2b$ version
      const salt2b = bcrypt.genSaltSync().replace(/\$2a\$/, "$2b$");
      const hash2b = bcrypt.hashSync("world", salt2b);
      expect(hash2b.substring(0,4)).toBe("$2b$");
      expect(bcrypt.compareSync("world", hash2b)).toBe(true);
    });

    test('should handle unicode strings', () => {
      const unicode = "ä☺𠜎️☁";
      const salt = bcrypt.genSaltSync();
      const hash = bcrypt.hashSync(unicode, salt);
      expect(bcrypt.compareSync(unicode, hash)).toBe(true);
    });
  });

  describe('compatibility', () => {
    test('should handle rounds out of bounds correctly', () => {
      const salt1 = bcrypt.genSaltSync(0); // $10$ like not set
      const salt2 = binding.genSaltSync(0);
      expect(salt1.substring(0, 7)).toBe("$2a$10$");
      expect(['$2a$10$', '$2b$10$']).toContain(salt2.substring(0, 7));

      const salt3 = bcrypt.genSaltSync(3); // $04$ is lower cap
      const salt4 = bcrypt.genSaltSync(3);
      expect(salt3.substring(0, 7)).toBe("$2a$04$");
      expect(salt4.substring(0, 7)).toBe("$2a$04$");

      const salt5 = bcrypt.genSaltSync(32); // $31$ is upper cap
      const salt6 = bcrypt.genSaltSync(32);
      expect(salt5.substring(0, 7)).toBe("$2a$31$");
      expect(salt6.substring(0, 7)).toBe("$2a$31$");
    });

    test('should match native bcrypt output', () => {
      const pass = fs.readFileSync(path.join(__dirname, "quickbrown.txt"), 'utf8');
      const salt = bcrypt.genSaltSync();
      const compatSalt = salt.replace(/^\$2a\$/, '$2b$');
      const hash1 = binding.hashSync(pass, compatSalt);
      const hash2 = bcrypt.hashSync(pass, salt);
      const compatHash2 = hash2.replace(/^\$2a\$/, '$2b$');
      expect(hash1).toBe(compatHash2);
    });
  });

  describe('promise API', () => {
    test('should support promise chain', async () => {
      const salt = await bcrypt.genSalt(10);
      expect(salt).toBeTruthy();
      
      const hash = await bcrypt.hash("hello", salt);
      expect(hash).toBeTruthy();
      
      const result = await bcrypt.compare("hello", hash);
      expect(result).toBeTruthy();
      
      const defaultSalt = await bcrypt.genSalt();
      expect(defaultSalt).toBeTruthy();
    });
  });

  describe('error handling', () => {
    test('should handle invalid salt', () => {
      expect(() => bcrypt.hashSync("hello", "invalid_salt")).toThrow();
    });

    test('should handle out of bounds rounds', () => {
      // Test upper bound (> 31 should clamp to 31)
      const saltUpper = bcrypt.genSaltSync(33);
      expect(bcrypt.getRounds(saltUpper)).toBe(31);

      // Test lower bound (< 4 should clamp to 4)
      const saltLower = bcrypt.genSaltSync(2);
      expect(bcrypt.getRounds(saltLower)).toBe(4);

      // Test default when 0 is provided (should use 10)
      const saltZero = bcrypt.genSaltSync(0);
      expect(bcrypt.getRounds(saltZero)).toBe(10);
    });

    test('should handle invalid string/salt combinations', () => {
      // Match the actual error messages from the implementation
      expect(() => bcrypt.hashSync(null, "salt")).toThrow(/Illegal arguments: object, string/);
      expect(() => bcrypt.hashSync("string", null)).toThrow(/Illegal arguments: string, object/);
    });

    test('should validate salt format', () => {
      expect(() => bcrypt.hashSync("test", "$1$invalid")).toThrow(/Invalid salt version/);
      expect(() => bcrypt.hashSync("test", "$2z$10$invalid")).toThrow(/Invalid salt revision/);
    });
  });

  describe('API validation', () => {
    test('getRounds should work', () => {
      const hash = bcrypt.hashSync("test", 10);
      expect(bcrypt.getRounds(hash)).toBe(10);
    });

    test('getSalt should work', () => {
      const fullSalt = bcrypt.genSaltSync(10);
      const hash = bcrypt.hashSync("test", fullSalt);
      expect(bcrypt.getSalt(hash)).toBe(fullSalt);
    });

    test('should handle invalid input types', () => {
      expect(() => bcrypt.getRounds(null)).toThrow();
      expect(() => bcrypt.getSalt(null)).toThrow();
      expect(() => bcrypt.compareSync(null, null)).toThrow();
    });
  });

  describe('async operations', () => {
    test('genSalt should work with callback', (done) => {
      bcrypt.genSalt(10, (err, salt) => {
        expect(err).toBeFalsy();
        expect(salt).toBeTruthy();
        expect(typeof salt).toBe('string');
        expect(salt.length).toBeGreaterThan(0);
        done();
      });
    });

    test('hash should work with callback', (done) => {
      bcrypt.hash("hello", 10, (err, hash) => {
        expect(err).toBeFalsy();
        expect(hash).toBeTruthy();
        done();
      });
    });

    test('compare should work with callback', (done) => {
      const hash = bcrypt.hashSync("hello", 10);
      bcrypt.compare("hello", hash, (err, result) => {
        expect(err).toBeFalsy();
        expect(result).toBeTruthy();
        done();
      });
    });
  });

  describe('benchmarking', () => {
    test('should handle maximum input length', () => {
      const salt = bcrypt.genSaltSync(4);
      let s = "";
      let last = null;
      
      while (s.length < 100) {
        s += "0";
        const hash = bcrypt.hashSync(s, salt);
        if (hash === last) {
          break;
        }
        last = hash;
      }
      expect(s.length).toBeLessThan(100);
    });
  });
}); 