pragma circom 2.2.3;

include "circomlib/circuits/comparators.circom";

/// @title EvalLogicPostfix
/// @notice Evaluates a postfix logical expression over boolean predicate results.
/// @dev Token encoding uses parallel arrays:
/// @dev   tokenTypes[i] = 0 for REF, 1 for AND, 2 for OR, 3 for NOT
/// @dev   tokenValues[i] stores the predicate index for REF, otherwise 0
/// @dev Inactive slots are ignored; only the prefix [0, exprLen) is evaluated.
/// @dev The expression is assumed to be well-formed. The circuit additionally enforces
/// @dev enough stack operands for each operator and that exactly one stack item remains.
template EvalLogicPostfix(MAX_TOKENS, MAX_PREDICATES) {
    signal input predicateResults[MAX_PREDICATES];
    signal input tokenTypes[MAX_TOKENS];
    signal input tokenValues[MAX_TOKENS];
    signal input exprLen;
    signal output out;

    signal sp[MAX_TOKENS + 1];
    signal stack[MAX_TOKENS + 1][MAX_TOKENS + 1];

    signal isActive[MAX_TOKENS];
    signal isInactive[MAX_TOKENS];
    signal isRef[MAX_TOKENS];
    signal isAndOp[MAX_TOKENS];
    signal isOrOp[MAX_TOKENS];
    signal isNotOp[MAX_TOKENS];
    signal isBinary[MAX_TOKENS];

    signal ge1[MAX_TOKENS];
    signal ge2[MAX_TOKENS];

    signal refMatchCount[MAX_TOKENS][MAX_PREDICATES + 1];
    signal refValueAccum[MAX_TOKENS][MAX_PREDICATES + 1];
    signal refSelected[MAX_TOKENS][MAX_PREDICATES];
    signal refProduct[MAX_TOKENS][MAX_PREDICATES];
    signal refValue[MAX_TOKENS];

    signal activeRef[MAX_TOKENS];
    signal activeUnary[MAX_TOKENS];
    signal activeBinary[MAX_TOKENS];
    signal activeOpValue[MAX_TOKENS];

    signal selTop1[MAX_TOKENS][MAX_TOKENS + 1];
    signal selTop2[MAX_TOKENS][MAX_TOKENS + 1];
    signal selPush[MAX_TOKENS][MAX_TOKENS + 1];
    signal selWriteUnary[MAX_TOKENS][MAX_TOKENS + 1];
    signal selWriteBinary[MAX_TOKENS][MAX_TOKENS + 1];

    signal top1Term[MAX_TOKENS][MAX_TOKENS + 1];
    signal top2Term[MAX_TOKENS][MAX_TOKENS + 1];
    signal top1[MAX_TOKENS];
    signal top2[MAX_TOKENS];

    signal andValue[MAX_TOKENS];
    signal orValue[MAX_TOKENS];
    signal notValue[MAX_TOKENS];
    signal binaryTermAnd[MAX_TOKENS];
    signal binaryTermOr[MAX_TOKENS];
    signal binaryValue[MAX_TOKENS];

    signal pushPick[MAX_TOKENS][MAX_TOKENS + 1];
    signal pushKeep[MAX_TOKENS][MAX_TOKENS + 1];
    signal pushCandidate[MAX_TOKENS][MAX_TOKENS + 1];

    signal unaryPick[MAX_TOKENS][MAX_TOKENS + 1];
    signal unaryKeep[MAX_TOKENS][MAX_TOKENS + 1];
    signal unaryCandidate[MAX_TOKENS][MAX_TOKENS + 1];

    signal binaryPick[MAX_TOKENS][MAX_TOKENS + 1];
    signal binaryKeep[MAX_TOKENS][MAX_TOKENS + 1];
    signal binaryCandidate[MAX_TOKENS][MAX_TOKENS + 1];

    signal termRef[MAX_TOKENS][MAX_TOKENS + 1];
    signal termUnary[MAX_TOKENS][MAX_TOKENS + 1];
    signal termBinary[MAX_TOKENS][MAX_TOKENS + 1];
    signal termInactive[MAX_TOKENS][MAX_TOKENS + 1];

    signal spTermRef[MAX_TOKENS];
    signal spTermUnary[MAX_TOKENS];
    signal spTermBinary[MAX_TOKENS];
    signal spTermInactive[MAX_TOKENS];

    component lenLt = LessThan(32);
    component ltActive[MAX_TOKENS];
    component lt1[MAX_TOKENS];
    component lt2[MAX_TOKENS];
    component eqRef[MAX_TOKENS];
    component eqAnd[MAX_TOKENS];
    component eqOr[MAX_TOKENS];
    component eqNot[MAX_TOKENS];
    component eqTop1[MAX_TOKENS][MAX_TOKENS + 1];
    component eqTop2[MAX_TOKENS][MAX_TOKENS + 1];
    component eqPush[MAX_TOKENS][MAX_TOKENS + 1];
    component eqWriteUnary[MAX_TOKENS][MAX_TOKENS + 1];
    component eqWriteBinary[MAX_TOKENS][MAX_TOKENS + 1];
    component refIndexEq[MAX_TOKENS][MAX_PREDICATES];

    for (var i = 0; i < MAX_TOKENS; i++) {
        ltActive[i] = LessThan(32);
        lt1[i] = LessThan(32);
        lt2[i] = LessThan(32);

        eqRef[i] = IsEqual();
        eqAnd[i] = IsEqual();
        eqOr[i] = IsEqual();
        eqNot[i] = IsEqual();

        for (var j = 0; j < MAX_TOKENS + 1; j++) {
            eqTop1[i][j] = IsEqual();
            eqTop2[i][j] = IsEqual();
            eqPush[i][j] = IsEqual();
            eqWriteUnary[i][j] = IsEqual();
            eqWriteBinary[i][j] = IsEqual();
        }

        for (var j = 0; j < MAX_PREDICATES; j++) {
            refIndexEq[i][j] = IsEqual();
        }
    }

    sp[0] <== 0;
    for (var j = 0; j < MAX_TOKENS + 1; j++) {
        stack[0][j] <== 0;
    }

    lenLt.in[0] <== exprLen;
    lenLt.in[1] <== MAX_TOKENS + 1;
    lenLt.out === 1;

    for (var i = 0; i < MAX_TOKENS; i++) {
        ltActive[i].in[0] <== i;
        ltActive[i].in[1] <== exprLen;
        isActive[i] <== ltActive[i].out;
        isInactive[i] <== 1 - isActive[i];

        eqRef[i].in[0] <== tokenTypes[i];
        eqRef[i].in[1] <== 0;
        isRef[i] <== eqRef[i].out;

        eqAnd[i].in[0] <== tokenTypes[i];
        eqAnd[i].in[1] <== 1;
        isAndOp[i] <== eqAnd[i].out;

        eqOr[i].in[0] <== tokenTypes[i];
        eqOr[i].in[1] <== 2;
        isOrOp[i] <== eqOr[i].out;

        eqNot[i].in[0] <== tokenTypes[i];
        eqNot[i].in[1] <== 3;
        isNotOp[i] <== eqNot[i].out;

        isBinary[i] <== isAndOp[i] + isOrOp[i];
        activeRef[i] <== isActive[i] * isRef[i];
        activeUnary[i] <== isActive[i] * isNotOp[i];
        activeBinary[i] <== isActive[i] * isBinary[i];

        // Active tokens must decode to exactly one supported token type.
        isActive[i] * ((isRef[i] + isAndOp[i] + isOrOp[i] + isNotOp[i]) - 1) === 0;

        refMatchCount[i][0] <== 0;
        refValueAccum[i][0] <== 0;
        for (var j = 0; j < MAX_PREDICATES; j++) {
            refIndexEq[i][j].in[0] <== tokenValues[i];
            refIndexEq[i][j].in[1] <== j;

            refSelected[i][j] <== isRef[i] * refIndexEq[i][j].out;
            refProduct[i][j] <== refSelected[i][j] * predicateResults[j];
            refMatchCount[i][j + 1] <== refMatchCount[i][j] + refIndexEq[i][j].out;
            refValueAccum[i][j + 1] <== refValueAccum[i][j] + refProduct[i][j];
        }

        // REF tokens must reference exactly one predicate; operators require tokenValue = 0.
        activeRef[i] * (refMatchCount[i][MAX_PREDICATES] - 1) === 0;
        activeOpValue[i] <== (isAndOp[i] + isOrOp[i] + isNotOp[i]) * tokenValues[i];
        isActive[i] * activeOpValue[i] === 0;
        refValue[i] <== refValueAccum[i][MAX_PREDICATES];
        refValue[i] * (refValue[i] - 1) === 0;

        lt1[i].in[0] <== sp[i];
        lt1[i].in[1] <== 1;
        ge1[i] <== 1 - lt1[i].out;

        lt2[i].in[0] <== sp[i];
        lt2[i].in[1] <== 2;
        ge2[i] <== 1 - lt2[i].out;

        activeUnary[i] * (1 - ge1[i]) === 0;
        activeBinary[i] * (1 - ge2[i]) === 0;

        for (var j = 0; j < MAX_TOKENS + 1; j++) {
            eqTop1[i][j].in[0] <== sp[i];
            eqTop1[i][j].in[1] <== j + 1;
            selTop1[i][j] <== eqTop1[i][j].out;

            eqTop2[i][j].in[0] <== sp[i];
            eqTop2[i][j].in[1] <== j + 2;
            selTop2[i][j] <== eqTop2[i][j].out;

            eqPush[i][j].in[0] <== sp[i];
            eqPush[i][j].in[1] <== j;
            selPush[i][j] <== eqPush[i][j].out;

            eqWriteUnary[i][j].in[0] <== sp[i];
            eqWriteUnary[i][j].in[1] <== j + 1;
            selWriteUnary[i][j] <== eqWriteUnary[i][j].out;

            eqWriteBinary[i][j].in[0] <== sp[i];
            eqWriteBinary[i][j].in[1] <== j + 2;
            selWriteBinary[i][j] <== eqWriteBinary[i][j].out;

            top1Term[i][j] <== selTop1[i][j] * stack[i][j];
            top2Term[i][j] <== selTop2[i][j] * stack[i][j];
        }

        var accTop1 = 0;
        var accTop2 = 0;
        for (var j = 0; j < MAX_TOKENS + 1; j++) {
            accTop1 += top1Term[i][j];
            accTop2 += top2Term[i][j];
        }

        top1[i] <== accTop1;
        top2[i] <== accTop2;
        top1[i] * (top1[i] - 1) === 0;
        top2[i] * (top2[i] - 1) === 0;

        andValue[i] <== top2[i] * top1[i];
        orValue[i] <== top2[i] + top1[i] - (top2[i] * top1[i]);
        notValue[i] <== 1 - top1[i];
        binaryTermAnd[i] <== isAndOp[i] * andValue[i];
        binaryTermOr[i] <== isOrOp[i] * orValue[i];
        binaryValue[i] <== binaryTermAnd[i] + binaryTermOr[i];

        for (var j = 0; j < MAX_TOKENS + 1; j++) {
            pushPick[i][j] <== selPush[i][j] * refValue[i];
            pushKeep[i][j] <== (1 - selPush[i][j]) * stack[i][j];
            pushCandidate[i][j] <== pushPick[i][j] + pushKeep[i][j];

            unaryPick[i][j] <== selWriteUnary[i][j] * notValue[i];
            unaryKeep[i][j] <== (1 - selWriteUnary[i][j]) * stack[i][j];
            unaryCandidate[i][j] <== unaryPick[i][j] + unaryKeep[i][j];

            binaryPick[i][j] <== selWriteBinary[i][j] * binaryValue[i];
            binaryKeep[i][j] <== (1 - selWriteBinary[i][j]) * stack[i][j];
            binaryCandidate[i][j] <== binaryPick[i][j] + binaryKeep[i][j];

            termRef[i][j] <== activeRef[i] * pushCandidate[i][j];
            termUnary[i][j] <== activeUnary[i] * unaryCandidate[i][j];
            termBinary[i][j] <== activeBinary[i] * binaryCandidate[i][j];
            termInactive[i][j] <== isInactive[i] * stack[i][j];

            stack[i + 1][j] <== termRef[i][j] + termUnary[i][j] + termBinary[i][j] + termInactive[i][j];
            stack[i + 1][j] * (stack[i + 1][j] - 1) === 0;
        }

        spTermRef[i] <== activeRef[i] * (sp[i] + 1);
        spTermUnary[i] <== activeUnary[i] * sp[i];
        spTermBinary[i] <== activeBinary[i] * (sp[i] - 1);
        spTermInactive[i] <== isInactive[i] * sp[i];
        sp[i + 1] <== spTermRef[i] + spTermUnary[i] + spTermBinary[i] + spTermInactive[i];
    }

    sp[MAX_TOKENS] === 1;
    out <== stack[MAX_TOKENS][0];
    out * (out - 1) === 0;
}
