pragma circom 2.2.3;

include "show.circom";

/// @title ShowMultiCredentials
/// @notice Evaluates verifier predicates over a flattened claim namespace from several prepared credentials.
/// @dev Prepare still runs once per credential. This wrapper only sizes the Show claim array as
/// `mCredentials * nClaimsPerCredential`; claim refs are flattened as
/// `credentialIndex * nClaimsPerCredential + claimIndex`.
template ShowMultiCredentials(
    mCredentials,
    nClaimsPerCredential,
    maxPredicates,
    maxLogicTokens,
    valueBits
) {
    assert(mCredentials >= 2);
    assert(nClaimsPerCredential >= 1);
    var nClaims = mCredentials * nClaimsPerCredential;

    signal input deviceKeyX;
    signal input deviceKeyY;
    signal input messageHash;
    signal input sig_r;
    signal input sig_s_inverse;
    signal input predicateLen;
    signal input claimValues[nClaims];
    signal input predicateClaimRefs[maxPredicates];
    signal input predicateOps[maxPredicates];
    signal input predicateRhsIsRef[maxPredicates];
    signal input predicateRhsValues[maxPredicates];
    signal input tokenTypes[maxLogicTokens];
    signal input tokenValues[maxLogicTokens];
    signal input exprLen;

    signal output expressionResult;

    component show = Show(nClaims, maxPredicates, maxLogicTokens, valueBits);
    show.deviceKeyX <== deviceKeyX;
    show.deviceKeyY <== deviceKeyY;
    show.messageHash <== messageHash;
    show.sig_r <== sig_r;
    show.sig_s_inverse <== sig_s_inverse;
    show.predicateLen <== predicateLen;
    show.claimValues <== claimValues;
    show.predicateClaimRefs <== predicateClaimRefs;
    show.predicateOps <== predicateOps;
    show.predicateRhsIsRef <== predicateRhsIsRef;
    show.predicateRhsValues <== predicateRhsValues;
    show.tokenTypes <== tokenTypes;
    show.tokenValues <== tokenValues;
    show.exprLen <== exprLen;

    expressionResult <== show.expressionResult;
}
