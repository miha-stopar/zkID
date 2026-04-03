pragma circom 2.2.3;

include "circomlib/circuits/comparators.circom";

/// @title EvalPredicate
/// @notice Evaluates one atomic predicate over canonically encoded claim values.
/// @dev Assumes `claimValue` and `compareValue` are integers in [0, 2^VALUE_BITS).
/// @dev Operator encoding:
/// @dev   0 = <=
/// @dev   1 = >=
/// @dev   2 = ==
template EvalPredicate(VALUE_BITS) {
    signal input claimValue;
    signal input op;
    signal input compareValue;

    signal output out;

    component eqLe = IsEqual();
    component eqGe = IsEqual();
    component eqEq = IsEqual();

    eqLe.in[0] <== op;
    eqLe.in[1] <== 0;

    eqGe.in[0] <== op;
    eqGe.in[1] <== 1;

    eqEq.in[0] <== op;
    eqEq.in[1] <== 2;

    signal isLe <== eqLe.out;
    signal isGe <== eqGe.out;
    signal isEq <== eqEq.out;

    // Exactly one supported operator must be selected.
    (isLe + isGe + isEq) - 1 === 0;

    component leCheck = LessEqThan(VALUE_BITS);
    leCheck.in[0] <== claimValue;
    leCheck.in[1] <== compareValue;

    // Reuse <= by swapping operands for >=.
    component geCheck = LessEqThan(VALUE_BITS);
    geCheck.in[0] <== compareValue;
    geCheck.in[1] <== claimValue;

    component eqCheck = IsEqual();
    eqCheck.in[0] <== claimValue;
    eqCheck.in[1] <== compareValue;

    signal leResult <== isLe * leCheck.out;
    signal geResult <== isGe * geCheck.out;
    signal eqResult <== isEq * eqCheck.out;
    signal rawResult <== leResult + geResult + eqResult;

    out <== rawResult;
    out * (out - 1) === 0;
}