pragma circom 2.2.3;

include "jwt.circom";

/// @title Prepare2SdJwt
/// @notice Verifies two SD-JWT credentials and exposes a flattened claim namespace.
/// @dev Each embedded JWT preprocessor verifies one issuer signature, checks disclosed
/// claim membership, extracts normalized claims, and extracts the device binding key.
/// The two credentials must bind to the same device key.
template Prepare2SdJwt(
    maxMessageLength,
    maxB64PayloadLength,
    maxMatches,
    maxSubstringLength,
    maxClaimsLength
) {
    assert(maxMatches >= 2);
    var maxClaims = maxMatches - 2;

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

    component jwt0 = JWT(maxMessageLength, maxB64PayloadLength, maxMatches, maxSubstringLength, maxClaimsLength);
    jwt0.message <== message0;
    jwt0.messageLength <== messageLength0;
    jwt0.periodIndex <== periodIndex0;
    jwt0.sig_r <== sig_r0;
    jwt0.sig_s_inverse <== sig_s_inverse0;
    jwt0.pubKeyX <== pubKeyX0;
    jwt0.pubKeyY <== pubKeyY0;
    jwt0.matchesCount <== matchesCount0;
    jwt0.matchSubstring <== matchSubstring0;
    jwt0.matchLength <== matchLength0;
    jwt0.matchIndex <== matchIndex0;
    jwt0.claims <== claims0;
    jwt0.claimLengths <== claimLengths0;
    jwt0.decodeFlags <== decodeFlags0;
    jwt0.claimFormats <== claimFormats0;

    component jwt1 = JWT(maxMessageLength, maxB64PayloadLength, maxMatches, maxSubstringLength, maxClaimsLength);
    jwt1.message <== message1;
    jwt1.messageLength <== messageLength1;
    jwt1.periodIndex <== periodIndex1;
    jwt1.sig_r <== sig_r1;
    jwt1.sig_s_inverse <== sig_s_inverse1;
    jwt1.pubKeyX <== pubKeyX1;
    jwt1.pubKeyY <== pubKeyY1;
    jwt1.matchesCount <== matchesCount1;
    jwt1.matchSubstring <== matchSubstring1;
    jwt1.matchLength <== matchLength1;
    jwt1.matchIndex <== matchIndex1;
    jwt1.claims <== claims1;
    jwt1.claimLengths <== claimLengths1;
    jwt1.decodeFlags <== decodeFlags1;
    jwt1.claimFormats <== claimFormats1;

    jwt0.KeyBindingX === jwt1.KeyBindingX;
    jwt0.KeyBindingY === jwt1.KeyBindingY;

    signal output normalizedClaimValuesAll[2 * maxClaims];
    for (var i = 0; i < maxClaims; i++) {
        normalizedClaimValuesAll[i] <== jwt0.normalizedClaimValues[i];
        normalizedClaimValuesAll[maxClaims + i] <== jwt1.normalizedClaimValues[i];
    }

    signal output KeyBindingX <== jwt0.KeyBindingX;
    signal output KeyBindingY <== jwt0.KeyBindingY;
}
