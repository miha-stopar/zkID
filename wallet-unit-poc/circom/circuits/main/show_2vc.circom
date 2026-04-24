// Track A (Option 2): Show over 4 claim slots = two SD-JWTs × (maxMatches − 2) claims.
pragma circom 2.2.3;

include "../show.circom";

component main {public [deviceKeyX, deviceKeyY]} = Show(4, 2, 8, 64);
