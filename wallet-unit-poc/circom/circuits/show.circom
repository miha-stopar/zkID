pragma circom 2.2.3;

include "ecdsa/ecdsa.circom";
include "components/expression.circom";

/// @title Show
/// @notice Verifies device binding and evaluates a logical expression over predicate results.
/// @param nClaims: number of claim field elements available for predicate references
/// @param maxPredicates: maximum number of predicates to evaluate
/// @param maxLogicTokens: capacity of the RPN token array for the logical expression
/// @param valueBits: bit width for claim/compare values in generalized predicates
///
/// Logical expression token encoding (postfix):
///   tokenTypes[i]: 0=REF, 1=AND, 2=OR, 3=NOT
///   tokenValues[i]: predicate index for REF, else 0
template Show(nClaims, maxPredicates, maxLogicTokens, valueBits) {
    signal input deviceKeyX;
    signal input deviceKeyY;
    signal input messageHash;
    signal input sig_r;
    signal input sig_s_inverse;

    // Generalized predicate phase inputs
    signal input predicateLen;
    signal input claimValues[nClaims];
    signal input predicateClaimRefs[maxPredicates];
    signal input predicateOps[maxPredicates];
    signal input predicateCompareValues[maxPredicates];

    // Logical expression over predicate results in Reverse Polish Notation.
    signal input tokenTypes[maxLogicTokens];
    signal input tokenValues[maxLogicTokens];
    signal input exprLen;

    // Output: result of the logical expression over all predicate results
    signal output expressionResult;

    component ecdsa = ECDSA();
    ecdsa.s_inverse <== sig_s_inverse;
    ecdsa.r <== sig_r;
    ecdsa.m <== messageHash;
    ecdsa.pubKeyX <== deviceKeyX;
    ecdsa.pubKeyY <== deviceKeyY;

    // Evaluate generalized predicates and then the postfix boolean expression
    component expressionEval = ExpressionEvaluator(nClaims, maxPredicates, maxLogicTokens, valueBits);
    expressionEval.claimValues <== claimValues;
    expressionEval.predicateLen <== predicateLen;
    expressionEval.predicateClaimRefs <== predicateClaimRefs;
    expressionEval.predicateOps <== predicateOps;
    expressionEval.predicateCompareValues <== predicateCompareValues;
    expressionEval.tokenTypes <== tokenTypes;
    expressionEval.tokenValues <== tokenValues;
    expressionEval.exprLen <== exprLen;
    expressionResult <== expressionEval.finalResult;
}

