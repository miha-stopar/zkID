pragma circom 2.2.3;

include "eval-predicates.circom";
include "logical-expressions.circom";

/// @title ExpressionEvaluator
/// @notice Two-phase generalized predicate evaluation.
/// @dev Phase 1: evaluate atomic predicates over claim values.
/// @dev Phase 2: evaluate a postfix boolean expression over predicate results.
/// @dev Claims are referenced by integer indices into `claimValues`.
/// @dev Claim values must already be canonically encoded as field elements.
template ExpressionEvaluator(N_CLAIMS, MAX_PREDICATES, MAX_EXPR_TOKENS, VALUE_BITS) {
    signal input claimValues[N_CLAIMS];

    // Predicate tuples: [claimRef, op, compareValue]
    signal input predicateLen;
    signal input predicateClaimRefs[MAX_PREDICATES];
    signal input predicateOps[MAX_PREDICATES];
    signal input predicateCompareValues[MAX_PREDICATES];

    // Postfix expression token arrays.
    // tokenTypes[i]: 0=REF, 1=AND, 2=OR, 3=NOT
    // tokenValues[i]: predicate index for REF, else 0
    signal input tokenTypes[MAX_EXPR_TOKENS];
    signal input tokenValues[MAX_EXPR_TOKENS];
    signal input exprLen;

    signal output predicateResults[MAX_PREDICATES];
    signal output finalResult;

    component predicatePhase = EvalPredicates(N_CLAIMS, MAX_PREDICATES, VALUE_BITS);
    predicatePhase.claimValues <== claimValues;
    predicatePhase.predicateLen <== predicateLen;
    predicatePhase.predicateClaimRefs <== predicateClaimRefs;
    predicatePhase.predicateOps <== predicateOps;
    predicatePhase.predicateCompareValues <== predicateCompareValues;

    predicateResults <== predicatePhase.predicateResults;

    component logicPhase = EvalLogicPostfix(MAX_EXPR_TOKENS, MAX_PREDICATES);
    logicPhase.predicateResults <== predicateResults;
    logicPhase.tokenTypes <== tokenTypes;
    logicPhase.tokenValues <== tokenValues;
    logicPhase.exprLen <== exprLen;

    finalResult <== logicPhase.out;
}
