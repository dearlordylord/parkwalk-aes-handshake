import {
  createChallenge,
  decodeTimestamp,
  EmptyPark,
  putChallenge,
  putSolution,
  SecretKey,
} from './parkwalk-core';
import { xoroshiro128plus } from 'pure-rand';
import fc from 'fast-check';

const rngProperty = fc.integer().map((seed) => xoroshiro128plus(seed));

describe('lets park', () => {
  describe('createChallenge', () => {
    it('should create a challenge with a valid encoded timestamp and secret key', () => {
      fc.assert(
        fc.property(rngProperty, (rng) => {
          const timestamp = Date.now();
          const [{ encodedTimestamp, secretKey }] = createChallenge(timestamp)(rng);
          expect(encodedTimestamp).toContain(':');
          expect(secretKey).toBeInstanceOf(Buffer);
          expect(secretKey.length).toBe(16); // secretKey should be 16 bytes
        })
      );
    });
  });

  describe('decodeTimestamp', () => {
    it('should decode an encoded timestamp correctly', () => {
      fc.assert(
        fc.property(rngProperty, (rng) => {
          const timestamp = Date.now();
          const [{ encodedTimestamp, secretKey }] = createChallenge(timestamp)(rng);
          const decodedTimestamp = decodeTimestamp(encodedTimestamp, secretKey);
          expect(decodedTimestamp).toBe(timestamp);
        })
      );
    });
  });

  describe('Public Park State Transitions', () => {
    it('should correctly transition from EmptyPark to ParkWithChallenge', () => {
      fc.assert(
        fc.property(rngProperty, (rng) => {
          const timestamp = Date.now();
          const [{ encodedTimestamp }] = createChallenge(timestamp)(rng);
          const parkWithChallenge = putChallenge(encodedTimestamp)(EmptyPark);
          expect(parkWithChallenge._tag).toBe('ParkWithChallenge');
          expect(parkWithChallenge.encodedTimestamp).toBe(encodedTimestamp);
        })
      );
    });

    it('should correctly transition from ParkWithChallenge to SolvedPark', () => {
      fc.assert(
        fc.property(rngProperty, (rng) => {
          const timestamp = Date.now();
          const [{ encodedTimestamp, secretKey }] = createChallenge(timestamp)(rng);
          const parkWithChallenge = putChallenge(encodedTimestamp)(EmptyPark);
          const decodedTimestamp = decodeTimestamp(encodedTimestamp, secretKey);
          const solvedPark = putSolution(decodedTimestamp, secretKey.toString('hex') as SecretKey)(parkWithChallenge);
          expect(solvedPark._tag).toBe('SolvedPark');
          expect(solvedPark.timestamp).toBe(decodedTimestamp);
          expect(solvedPark.secretKey).toBe(secretKey.toString('hex'));
        })
      );
    });
  });
});
