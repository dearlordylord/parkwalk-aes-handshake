import { Either, left } from 'fp-ts/Either';
import { Int } from 'io-ts';
import * as t from 'io-ts';
import { pipe } from 'fp-ts/function';
import { PathReporter } from 'io-ts/PathReporter';

export const getFromEitherC =
  <E extends Error = Error, Err = unknown>(e?: string | ((e: Err) => E)) =>
    <A>(v: Either<Err, A>): A => {
      if (v._tag === 'Left') {
        if (typeof e === 'function') throw e(v.left);
        throw new Error(e || 'panic! getFromValidation: Left');
      }
      return v.right;
    };
export const castEitherC = getFromEitherC;

export type NonNegativeIntegerBrand = {
  readonly NonNegativeInteger: unique symbol;
};

export const nonNegativeIntegerCodec = t.brand(
  t.Int,
  (n): n is t.Branded<Int, NonNegativeIntegerBrand> => n >= 0,
  'NonNegativeInteger'
);

export type NonNegativeInteger = t.TypeOf<typeof nonNegativeIntegerCodec>;

export const castNonNegativeInteger = (p: number): NonNegativeInteger =>
  pipe(
    p,
    nonNegativeIntegerCodec.decode,
    castEitherC(`panic! wrong non negative integer ${p} for castNonNegativeInteger`));

export const showDecodeError = (e: t.Errors): string => PathReporter.report(left(e)).join('\n');

export const parseNonNegativeInteger = (s: string) => {
  const n = parseInt(s, 10);
  if (isNaN(n)) {
    throw new Error(`parseNonNegativeInteger: ${s} is not a number`);
  }
  if (n.toString(10) !== s) {
    throw new Error(`parseNonNegativeInteger: ${s} is not a valid number`);
  }
  return castNonNegativeInteger(n);
}
