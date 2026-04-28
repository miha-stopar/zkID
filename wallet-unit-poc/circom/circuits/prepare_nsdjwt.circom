pragma circom 2.2.3;

include "jwt.circom";

/// @title PrepareNSdJwt
/// @notice Verifies a fixed number of SD-JWT credentials and exposes one flattened claim namespace.
/// @dev `nCredentials` is fixed at compile time. This is not a runtime-variable circuit.
/// Every credential is verified, and every credential must bind to the same device key.
template PrepareNSdJwt(
    nCredentials,
    maxMessageLength,
    maxB64PayloadLength,
    maxMatches,
    maxSubstringLength,
    maxClaimsLength
) {
    assert(nCredentials >= 2);
    assert(maxMatches >= 2);
    var maxClaims = maxMatches - 2;

    signal input message[nCredentials][maxMessageLength];
    signal input messageLength[nCredentials];
    signal input periodIndex[nCredentials];
    signal input sig_r[nCredentials];
    signal input sig_s_inverse[nCredentials];
    signal input pubKeyX[nCredentials];
    signal input pubKeyY[nCredentials];
    signal input matchesCount[nCredentials];
    signal input matchSubstring[nCredentials][maxMatches][maxSubstringLength];
    signal input matchLength[nCredentials][maxMatches];
    signal input matchIndex[nCredentials][maxMatches];
    signal input claims[nCredentials][maxClaims][maxClaimsLength];
    signal input claimLengths[nCredentials][maxClaims];
    signal input decodeFlags[nCredentials][maxClaims];
    signal input claimFormats[nCredentials][maxClaims];

    component jwt[nCredentials];
    for (var credentialIndex = 0; credentialIndex < nCredentials; credentialIndex++) {
        jwt[credentialIndex] = JWT(
            maxMessageLength,
            maxB64PayloadLength,
            maxMatches,
            maxSubstringLength,
            maxClaimsLength
        );
        jwt[credentialIndex].message <== message[credentialIndex];
        jwt[credentialIndex].messageLength <== messageLength[credentialIndex];
        jwt[credentialIndex].periodIndex <== periodIndex[credentialIndex];
        jwt[credentialIndex].sig_r <== sig_r[credentialIndex];
        jwt[credentialIndex].sig_s_inverse <== sig_s_inverse[credentialIndex];
        jwt[credentialIndex].pubKeyX <== pubKeyX[credentialIndex];
        jwt[credentialIndex].pubKeyY <== pubKeyY[credentialIndex];
        jwt[credentialIndex].matchesCount <== matchesCount[credentialIndex];
        jwt[credentialIndex].matchSubstring <== matchSubstring[credentialIndex];
        jwt[credentialIndex].matchLength <== matchLength[credentialIndex];
        jwt[credentialIndex].matchIndex <== matchIndex[credentialIndex];
        jwt[credentialIndex].claims <== claims[credentialIndex];
        jwt[credentialIndex].claimLengths <== claimLengths[credentialIndex];
        jwt[credentialIndex].decodeFlags <== decodeFlags[credentialIndex];
        jwt[credentialIndex].claimFormats <== claimFormats[credentialIndex];
    }

    for (var credentialIndex = 1; credentialIndex < nCredentials; credentialIndex++) {
        jwt[0].KeyBindingX === jwt[credentialIndex].KeyBindingX;
        jwt[0].KeyBindingY === jwt[credentialIndex].KeyBindingY;
    }

    signal output normalizedClaimValuesAll[nCredentials * maxClaims];
    for (var credentialIndex = 0; credentialIndex < nCredentials; credentialIndex++) {
        for (var claimIndex = 0; claimIndex < maxClaims; claimIndex++) {
            normalizedClaimValuesAll[credentialIndex * maxClaims + claimIndex] <==
                jwt[credentialIndex].normalizedClaimValues[claimIndex];
        }
    }

    signal output KeyBindingX <== jwt[0].KeyBindingX;
    signal output KeyBindingY <== jwt[0].KeyBindingY;
}
