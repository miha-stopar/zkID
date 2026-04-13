export const PredicateFormat = {
  BOOL: 0,
  UINT: 1,
  ISO_DATE: 2,
  ROC_DATE: 3,
  STRING_EQ: 4,
} as const;

export type PredicateFormat = (typeof PredicateFormat)[keyof typeof PredicateFormat];

export function encodeValue(value: string, maxLen: number): bigint[] {
  const encoded: bigint[] = [];
  for (let i = 0; i < maxLen; i++) {
    if (i < value.length) {
      encoded.push(BigInt(value.charCodeAt(i)));
    } else {
      encoded.push(0n);
    }
  }
  return encoded;
}
