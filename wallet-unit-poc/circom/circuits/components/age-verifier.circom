pragma circom 2.1.6;

include "circomlib/circuits/comparators.circom";
include "@zk-email/circuits/utils/array.circom";

template AgeExtractor() {
    signal input YYMMDD[7];
    signal input currentYear;
    signal input currentMonth;
    signal input currentDay;
    signal output age;

    signal birthROCYear <== YYMMDD[0]*100 + YYMMDD[1]*10 + YYMMDD[2];
    signal birthYear    <== birthROCYear + 1911;
    signal birthMonth   <== YYMMDD[3]*10 + YYMMDD[4];
    signal birthDay     <== YYMMDD[5]*10 + YYMMDD[6];

    signal rawAge <== currentYear - birthYear;

    component mGt = GreaterThan(4);
    mGt.in[0] <== currentMonth;
    mGt.in[1] <== birthMonth;

    component mEq = IsEqual();
    mEq.in[0] <== currentMonth;
    mEq.in[1] <== birthMonth;

    component dGe = GreaterEqThan(5);
    dGe.in[0] <== currentDay;
    dGe.in[1] <== birthDay;

    signal hadBirthday;
    hadBirthday <== mGt.out + mEq.out * dGe.out;
    age <== rawAge - 1 + hadBirthday;
}

// ROC birthday format: "YYYMMDD" (7 digits, no separators)
template AgeVerifier(decodedLen) {
    signal input claim[decodedLen];
    signal input currentYear;
    signal input currentMonth;
    signal input currentDay;
    signal output ageAbove18;

    // Step 1: Find the 5th quote (opening quote of value)
    component isQuoteCmp[decodedLen];
    signal isQuote[decodedLen];
    signal quoteCount[decodedLen];
    for (var i = 0; i < decodedLen; i++) {
        isQuoteCmp[i] = IsEqual();
        isQuoteCmp[i].in[0] <== claim[i];
        isQuoteCmp[i].in[1] <== 34;
        isQuote[i] <== isQuoteCmp[i].out;
        quoteCount[i] <== (i == 0 ? 0 : quoteCount[i-1]) + isQuote[i];
    }
    quoteCount[decodedLen-1] === 6;

    // Step 2: Find index of 5th quote using one-hot encoding
    // The 5th quote is where quoteCount transitions from 4 to 5
    component isFifthQuote[decodedLen];
    signal fifthQuoteIdx[decodedLen];
    signal shiftAcc[decodedLen];
    for (var i = 0; i < decodedLen; i++) {
        isFifthQuote[i] = IsEqual();
        isFifthQuote[i].in[0] <== quoteCount[i];
        isFifthQuote[i].in[1] <== 5;
        // One-hot: 1 only at the exact position of the 5th quote
        fifthQuoteIdx[i] <== isFifthQuote[i].out * isQuote[i];
        // Accumulate index: sum(i * oneHot[i]) gives the position
        shiftAcc[i] <== (i == 0 ? 0 : shiftAcc[i-1]) + fifthQuoteIdx[i] * i;
    }
    // shift = position of 5th quote + 1 (skip the quote itself to get first digit)
    signal shift <== shiftAcc[decodedLen-1] + 1;

    // Step 3: Use VarShiftLeft to extract 7 consecutive bytes starting at the value
    component shifter = VarShiftLeft(decodedLen, 7);
    for (var i = 0; i < decodedLen; i++) {
        shifter.in[i] <== claim[i];
    }
    shifter.shift <== shift;

    // Step 4: Convert ASCII digits to numeric values
    signal birthDigits[7];
    for (var i = 0; i < 7; i++) {
        birthDigits[i] <== shifter.out[i] - 48;
    }

    component ageExtractor = AgeExtractor();
    ageExtractor.YYMMDD <== birthDigits;
    ageExtractor.currentYear <== currentYear;
    ageExtractor.currentMonth <== currentMonth;
    ageExtractor.currentDay <== currentDay;

    component ageCheck = GreaterThan(8);
    ageCheck.in[0] <== ageExtractor.age;
    ageCheck.in[1] <== 18;
    ageAbove18 <== ageCheck.out;
}

template AgeExtractorISO() {
    signal input digits[8]; // YYYYMMDD
    signal input currentYear;
    signal input currentMonth;
    signal input currentDay;
    signal output age;

    signal birthYear  <== digits[0]*1000 + digits[1]*100 + digits[2]*10 + digits[3];
    signal birthMonth <== digits[4]*10 + digits[5];
    signal birthDay   <== digits[6]*10 + digits[7];

    signal rawAge <== currentYear - birthYear;

    component mGt = GreaterThan(4);
    mGt.in[0] <== currentMonth;
    mGt.in[1] <== birthMonth;

    component mEq = IsEqual();
    mEq.in[0] <== currentMonth;
    mEq.in[1] <== birthMonth;

    component dGe = GreaterEqThan(5);
    dGe.in[0] <== currentDay;
    dGe.in[1] <== birthDay;

    signal hadBirthday;
    hadBirthday <== mGt.out + mEq.out * dGe.out;
    age <== rawAge - 1 + hadBirthday;
}

// ISO 8601 date format: "YYYY-MM-DD" (10 chars between quotes)
template AgeVerifierISO(decodedLen) {
    signal input claim[decodedLen];
    signal input currentYear;
    signal input currentMonth;
    signal input currentDay;
    signal output ageAbove18;

    // Step 1: Find the 5th quote
    component isQuoteCmp[decodedLen];
    signal isQuote[decodedLen];
    signal quoteCount[decodedLen];
    for (var i = 0; i < decodedLen; i++) {
        isQuoteCmp[i] = IsEqual();
        isQuoteCmp[i].in[0] <== claim[i];
        isQuoteCmp[i].in[1] <== 34;
        isQuote[i] <== isQuoteCmp[i].out;
        quoteCount[i] <== (i == 0 ? 0 : quoteCount[i-1]) + isQuote[i];
    }
    quoteCount[decodedLen-1] === 6;

    // Step 2: Find index of 5th quote
    component isFifthQuote[decodedLen];
    signal fifthQuoteIdx[decodedLen];
    signal shiftAcc[decodedLen];
    for (var i = 0; i < decodedLen; i++) {
        isFifthQuote[i] = IsEqual();
        isFifthQuote[i].in[0] <== quoteCount[i];
        isFifthQuote[i].in[1] <== 5;
        fifthQuoteIdx[i] <== isFifthQuote[i].out * isQuote[i];
        shiftAcc[i] <== (i == 0 ? 0 : shiftAcc[i-1]) + fifthQuoteIdx[i] * i;
    }
    // shift past the opening quote to first char: "YYYY-MM-DD"
    signal shift <== shiftAcc[decodedLen-1] + 1;

    // Step 3: Use VarShiftLeft to extract 10 consecutive bytes (YYYY-MM-DD)
    component shifter = VarShiftLeft(decodedLen, 10);
    for (var i = 0; i < decodedLen; i++) {
        shifter.in[i] <== claim[i];
    }
    shifter.shift <== shift;

    // Step 4: Extract digits, skipping dashes at positions 4 and 7
    // "YYYY-MM-DD" → positions 0-3: year, 4: dash, 5-6: month, 7: dash, 8-9: day
    signal birthDigits[8];
    birthDigits[0] <== shifter.out[0] - 48;
    birthDigits[1] <== shifter.out[1] - 48;
    birthDigits[2] <== shifter.out[2] - 48;
    birthDigits[3] <== shifter.out[3] - 48;
    shifter.out[4] === 45; // assert '-'
    birthDigits[4] <== shifter.out[5] - 48;
    birthDigits[5] <== shifter.out[6] - 48;
    shifter.out[7] === 45; // assert '-'
    birthDigits[6] <== shifter.out[8] - 48;
    birthDigits[7] <== shifter.out[9] - 48;

    component ageExtractor = AgeExtractorISO();
    ageExtractor.digits <== birthDigits;
    ageExtractor.currentYear <== currentYear;
    ageExtractor.currentMonth <== currentMonth;
    ageExtractor.currentDay <== currentDay;

    component ageCheck = GreaterThan(8);
    ageCheck.in[0] <== ageExtractor.age;
    ageCheck.in[1] <== 18;
    ageAbove18 <== ageCheck.out;
}
