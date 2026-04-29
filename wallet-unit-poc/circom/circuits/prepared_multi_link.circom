pragma circom 2.2.3;

/// @title PreparedMultiLink
/// @notice Links a multi-credential Show proof to already verified single-credential Prepare outputs.
/// @dev The shared vector must match ShowMultiCredentials:
///      [linkedDeviceKeyX, linkedDeviceKeyY, linkedClaimValues[0..nClaims]].
///      The expected values are public and should be taken from the Prepare proof public outputs.
template PreparedMultiLink(nClaims) {
    assert(nClaims >= 2);

    signal input expectedDeviceKeyX;
    signal input expectedDeviceKeyY;
    signal input expectedClaimValues[nClaims];

    signal output linkResult;
    signal output linkedDeviceKeyX;
    signal output linkedDeviceKeyY;
    signal output linkedClaimValues[nClaims];

    linkedDeviceKeyX <== expectedDeviceKeyX;
    linkedDeviceKeyY <== expectedDeviceKeyY;

    for (var i = 0; i < nClaims; i++) {
        linkedClaimValues[i] <== expectedClaimValues[i];
    }

    linkResult <== 1;
}
