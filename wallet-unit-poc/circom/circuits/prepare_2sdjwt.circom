pragma circom 2.2.3;

include "jwt.circom";

/// Track A / Option 2 (MULTI_VC_PLAN §4): two SD-JWT preprocessors in one Prepare R1CS.
/// Same device binding key is enforced across both credentials; normalized claims are
/// concatenated (VC0 slots, then VC1 slots) for the shared witness slice consumed by Show.
template Prepare2SdJwt(
    maxMessageLength,
    maxB64PayloadLength,
    maxMatches,
    maxSubstringLength,
    maxClaimsLength
) {
    assert(maxMatches >= 2);
    var maxClaims = maxMatches - 2;

    // --- VC0 (same interface as single `JWT`) ---
    signal input message0[maxMessageLength];
    signal input messageLength0;
    signal input periodIndex0;
    signal input sig_r0;
    signal input sig_s_inverse0;
    signal input pubKeyX0;
    signal input pubKeyY0;
    signal input matchesCount0;
    signal input matchSubstring0[maxMatches][maxSubstringLength];
    signal input matchLength0[maxMatches];
    signal input matchIndex0[maxMatches];
    signal input claims0[maxClaims][maxClaimsLength];
    signal input claimLengths0[maxClaims];
    signal input decodeFlags0[maxClaims];
    signal input claimFormats0[maxClaims];

    // --- VC1 ---
    signal input message1[maxMessageLength];
    signal input messageLength1;
    signal input periodIndex1;
    signal input sig_r1;
    signal input sig_s_inverse1;
    signal input pubKeyX1;
    signal input pubKeyY1;
    signal input matchesCount1;
    signal input matchSubstring1[maxMatches][maxSubstringLength];
    signal input matchLength1[maxMatches];
    signal input matchIndex1[maxMatches];
    signal input claims1[maxClaims][maxClaimsLength];
    signal input claimLengths1[maxClaims];
    signal input decodeFlags1[maxClaims];
    signal input claimFormats1[maxClaims];

    component j0 = JWT(maxMessageLength, maxB64PayloadLength, maxMatches, maxSubstringLength, maxClaimsLength);
    j0.message <== message0;
    j0.messageLength <== messageLength0;
    j0.periodIndex <== periodIndex0;
    j0.sig_r <== sig_r0;
    j0.sig_s_inverse <== sig_s_inverse0;
    j0.pubKeyX <== pubKeyX0;
    j0.pubKeyY <== pubKeyY0;
    j0.matchesCount <== matchesCount0;
    j0.matchSubstring <== matchSubstring0;
    j0.matchLength <== matchLength0;
    j0.matchIndex <== matchIndex0;
    j0.claims <== claims0;
    j0.claimLengths <== claimLengths0;
    j0.decodeFlags <== decodeFlags0;
    j0.claimFormats <== claimFormats0;

    component j1 = JWT(maxMessageLength, maxB64PayloadLength, maxMatches, maxSubstringLength, maxClaimsLength);
    j1.message <== message1;
    j1.messageLength <== messageLength1;
    j1.periodIndex <== periodIndex1;
    j1.sig_r <== sig_r1;
    j1.sig_s_inverse <== sig_s_inverse1;
    j1.pubKeyX <== pubKeyX1;
    j1.pubKeyY <== pubKeyY1;
    j1.matchesCount <== matchesCount1;
    j1.matchSubstring <== matchSubstring1;
    j1.matchLength <== matchLength1;
    j1.matchIndex <== matchIndex1;
    j1.claims <== claims1;
    j1.claimLengths <== claimLengths1;
    j1.decodeFlags <== decodeFlags1;
    j1.claimFormats <== claimFormats1;

    j0.KeyBindingX === j1.KeyBindingX;
    j0.KeyBindingY === j1.KeyBindingY;

    signal output normalizedClaimValuesAll[2 * maxClaims];
    for (var i = 0; i < maxClaims; i++) {
        normalizedClaimValuesAll[i] <== j0.normalizedClaimValues[i];
        normalizedClaimValuesAll[maxClaims + i] <== j1.normalizedClaimValues[i];
    }
    signal output KeyBindingX <== j0.KeyBindingX;
    signal output KeyBindingY <== j0.KeyBindingY;
}
