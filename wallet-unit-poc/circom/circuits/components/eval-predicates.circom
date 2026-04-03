pragma circom 2.2.3;

include "circomlib/circuits/comparators.circom";
include "eval-predicate.circom";

/// @title EvalPredicates
/// @notice Evaluates an array of atomic predicates over a fixed-size claim array.
/// @dev Claim references are integer indices into `claimValues`.
/// @dev Predicate tuple encoding per slot i:
/// @dev   [predicateClaimRefs[i], predicateOps[i], predicateCompareValues[i]]
/// @dev Operator encoding:
/// @dev   0 = <=
/// @dev   1 = >=
/// @dev   2 = ==
template EvalPredicates(N_CLAIMS, MAX_PREDICATES, VALUE_BITS) {
    signal input claimValues[N_CLAIMS];

    // Number of active predicate tuples in [0, MAX_PREDICATES]
    signal input predicateLen;

    signal input predicateClaimRefs[MAX_PREDICATES];
    signal input predicateOps[MAX_PREDICATES];
    signal input predicateCompareValues[MAX_PREDICATES];

    signal output predicateResults[MAX_PREDICATES];

    component claimRefEq[MAX_PREDICATES][N_CLAIMS];
    signal refSelected[MAX_PREDICATES][N_CLAIMS];
    signal refProduct[MAX_PREDICATES][N_CLAIMS];
    signal refCount[MAX_PREDICATES][N_CLAIMS + 1];
    signal refAccum[MAX_PREDICATES][N_CLAIMS + 1];
    signal selectedClaimValues[MAX_PREDICATES];
    component activeLt[MAX_PREDICATES];
    signal isActive[MAX_PREDICATES];
    signal effectiveClaimValue[MAX_PREDICATES];
    signal effectiveOp[MAX_PREDICATES];
    signal effectiveCompareValue[MAX_PREDICATES];
    component lenRange;
    component predicateEval[MAX_PREDICATES];

    // 0 <= predicateLen <= MAX_PREDICATES
    lenRange = LessThan(16);
    lenRange.in[0] <== predicateLen;
    lenRange.in[1] <== MAX_PREDICATES + 1;
    lenRange.out === 1;

    for (var i = 0; i < MAX_PREDICATES; i++) {
        activeLt[i] = LessThan(16);
        activeLt[i].in[0] <== i;
        activeLt[i].in[1] <== predicateLen;
        isActive[i] <== activeLt[i].out;

        refCount[i][0] <== 0;
        refAccum[i][0] <== 0;

        for (var j = 0; j < N_CLAIMS; j++) {
            claimRefEq[i][j] = IsEqual();
            claimRefEq[i][j].in[0] <== predicateClaimRefs[i];
            claimRefEq[i][j].in[1] <== j;

            refSelected[i][j] <== isActive[i] * claimRefEq[i][j].out;
            refProduct[i][j] <== refSelected[i][j] * claimValues[j];
            refCount[i][j + 1] <== refCount[i][j] + refSelected[i][j];
            refAccum[i][j + 1] <== refAccum[i][j] + refProduct[i][j];
        }

        // Active predicates must reference exactly one valid claim index.
        // Inactive predicates must reference none (count 0).
        refCount[i][N_CLAIMS] - isActive[i] === 0;

        selectedClaimValues[i] <== refAccum[i][N_CLAIMS];
        effectiveClaimValue[i] <== isActive[i] * selectedClaimValues[i];
        effectiveCompareValue[i] <== isActive[i] * predicateCompareValues[i];
        effectiveOp[i] <== isActive[i] * predicateOps[i] + (1 - isActive[i]) * 2;

        predicateEval[i] = EvalPredicate(VALUE_BITS);
        predicateEval[i].claimValue <== effectiveClaimValue[i];
        predicateEval[i].op <== effectiveOp[i];
        predicateEval[i].compareValue <== effectiveCompareValue[i];

        predicateResults[i] <== isActive[i] * predicateEval[i].out;
        predicateResults[i] * (predicateResults[i] - 1) === 0;
    }
}