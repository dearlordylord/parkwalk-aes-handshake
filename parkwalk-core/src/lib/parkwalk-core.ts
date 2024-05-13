import * as crypto from 'crypto';
import * as t from 'io-ts';
import * as tt from 'io-ts-types';
import { NonEmptyString } from 'io-ts-types';
import { pipe } from 'fp-ts/function';
import { RandomGenerator, xoroshiro128plus } from 'pure-rand';
import { State } from 'fp-ts/State';
import { Buffer } from 'buffer';
import {
  castEitherC,
  castNonNegativeInteger,
  NonNegativeInteger,
  parseNonNegativeInteger,
  showDecodeError
} from './utils';

export type EncodedTimestampEncryptedPartBrand = {
  readonly EncodedTimestampEncryptedPart: unique symbol;
};

const BYTE_RESTRICTION = 32;

export const encodedTimestampEncryptedPartCodec = t.brand(
  tt.NonEmptyString,
  (s): s is t.Branded<NonEmptyString, EncodedTimestampEncryptedPartBrand> => s.length === 32 /*doesn't matter much*/,
  'EncodedTimestampEncryptedPart'
);

export type EncodedTimestampEncryptedPart = t.TypeOf<typeof encodedTimestampEncryptedPartCodec>;

const castEncodedTimestampEncryptedPart = (encodedTimestampEncryptedPart: string): EncodedTimestampEncryptedPart =>
  pipe(
    encodedTimestampEncryptedPart,
    encodedTimestampEncryptedPartCodec.decode,
    castEitherC((e) => new Error(showDecodeError(e)))
  );

export type IVBrand = {
  readonly IV: unique symbol;
};

export const ivCodec = t.brand(
  tt.NonEmptyString,
  (s): s is t.Branded<NonEmptyString, IVBrand> => s.length === BYTE_RESTRICTION,
  'IV'
);

export type IV = t.TypeOf<typeof ivCodec>;

const castIV = (iv: string): IV =>
  pipe(
    iv,
    ivCodec.decode,
    castEitherC((e) => new Error(showDecodeError(e)))
  );

const CHALLENGE_SEPARATOR = ':';

export type ChallengeSeparator = typeof CHALLENGE_SEPARATOR;

export type EncodedTimestamp = `${EncodedTimestampEncryptedPart}${ChallengeSeparator}${IV}`;

export type SecretKeyBrand = {
  readonly SecretKey: unique symbol;
};

export const secretKeyCodec = t.brand(
  tt.NonEmptyString,
  (s): s is t.Branded<NonEmptyString, SecretKeyBrand> => s.length === BYTE_RESTRICTION,
  'SecretKey'
);

export type SecretKey = t.TypeOf<typeof secretKeyCodec>;

const castSecretKey = (secretKey: string): SecretKey =>
  pipe(
    secretKey,
    secretKeyCodec.decode,
    castEitherC((e) => new Error(showDecodeError(e)))
  );

type Challenge = {
  encodedTimestamp: EncodedTimestamp;
};

type PublicPark =
  | { _tag: 'EmptyPark' }
  | {
  encodedTimestamp: EncodedTimestamp;
  _tag: 'ParkWithChallenge';
}
  | {
  encodedTimestamp: EncodedTimestamp;
  secretKey: SecretKey;
  timestamp: number;
  _tag: 'SolvedPark';
};

export type EmptyPark = { _tag: 'EmptyPark' } & PublicPark;
export const EmptyPark: EmptyPark = Object.freeze({ _tag: 'EmptyPark' });
export type ParkWithChallenge = { _tag: 'ParkWithChallenge' } & PublicPark;
const _ParkWithChallenge = (encodedTimestamp: EncodedTimestamp): ParkWithChallenge =>
  Object.freeze({
    encodedTimestamp,
    _tag: 'ParkWithChallenge',
  });
export type SolvedPark = { _tag: 'SolvedPark' } & PublicPark;
const _SolvedPark = (encodedTimestamp: EncodedTimestamp, secretKey: SecretKey, timestamp: number): SolvedPark =>
  Object.freeze({
    encodedTimestamp,
    secretKey,
    timestamp,
    _tag: 'SolvedPark',
  });

const randN =
  (n: NonNegativeInteger): State<RandomGenerator, number[]> =>
    (rng) => {
      const r: number[] = Array.from({ length: n });
      for (let i = 0; i < n; i++) {
        const [n1, rng1] = rng.next();
        rng = rng1;
        r[i] = n1;
      }
      return [r, rng];
    };

export const createChallenge =
  (timestamp: number): State<RandomGenerator, { encodedTimestamp: EncodedTimestamp; secretKey: Buffer }> =>
    (rng) => {
      const [n1, rng1] = randN(castNonNegativeInteger(16))(rng);
      const secretKey = Buffer.from(n1);
      const [n2, rng2] = randN(castNonNegativeInteger(16))(rng1);
      const iv = Buffer.from(n2);
      const cipher = crypto.createCipheriv('aes-128-cbc', secretKey, iv);
      let encoded = cipher.update(timestamp.toString(), 'utf8', 'hex');
      encoded += cipher.final('hex'); // shake it off
      const encodedTimestamp: EncodedTimestamp = `${castEncodedTimestampEncryptedPart(
        encoded
      )}${CHALLENGE_SEPARATOR}${castIV(iv.toString('hex'))}`;
      return [{ encodedTimestamp, secretKey }, rng2];
    };

export const decodeTimestamp = (encodedTimestamp: EncodedTimestamp, secretKey: Buffer): number => {
  const [encoded, ivHex] = encodedTimestamp.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-128-cbc', secretKey, iv);
  let decoded = decipher.update(encoded, 'hex', 'utf8');
  decoded += decipher.final('utf8');
  return parseNonNegativeInteger(decoded);
};

export const putChallenge =
  (encodedTimestamp: EncodedTimestamp) =>
    (park: EmptyPark): ParkWithChallenge =>
      Object.freeze({
        ...park,
        encodedTimestamp,
        _tag: 'ParkWithChallenge',
      });

// not checked, careful
export const putSolution =
  (timestamp: number, secretKey: SecretKey) =>
    (park: ParkWithChallenge): SolvedPark =>
      Object.freeze({
        ...park,
        timestamp,
        secretKey,
        _tag: 'SolvedPark',
      });

// TODO model in Effect as 2 actors

const initialPark = EmptyPark;

// Bob:
const timestamp = Date.now();
const rng = xoroshiro128plus(crypto.randomInt(9999999));
const [{ encodedTimestamp, secretKey }, _rng1] = createChallenge(timestamp)(rng);
const parkWithChallenge = putChallenge(encodedTimestamp)(initialPark);

// Bob gives secret key to Alice

// Alice:
const decodedTimestamp = decodeTimestamp(parkWithChallenge.encodedTimestamp, secretKey);

const solvedPark = putSolution(decodedTimestamp, castSecretKey(secretKey.toString('hex')))(parkWithChallenge);
