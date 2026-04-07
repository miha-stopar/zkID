# Generalized Predicate Proofs for Verifiable Credentials

This design enables a credential holder to prove complex logical statements over multiple attributes without revealing the underlying values. The verifier validates the proof and obtains the boolean output of the logical expression, which indicates whether the policy is satisfied.

This is particularly useful for privacy preserving identity systems where users must prove eligibility conditions such as:

- `age >= 18`
- `employment_years >= 2 AND (50000 <= annual_income_eur <= 100000 OR account_balance_eur >= 10000)`
- `age >= 18 AND residency_country IN {"Netherlands","Belgium","Germany"}`

The construction supports arbitrary logical composition while keeping all claims private.

# Inputs

The proving system receives three inputs:

1. List of claim values (private)
2. List of predicates
3. Logical expression combining predicate results

# 1. Claim Values

Claims are the private attributes stored inside the credential. These values are never revealed to the verifier.

Example:

```
claims = {
  date_of_birth: "1990-03-20",
  country: "Netherlands",
  annual_income_eur: 52000
}
```

So the claim values are `("1990-03-20", "Netherlands", 52000)`.

# 2. Predicates

Predicates are boolean conditions evaluated over claim values. Each predicate evaluates to either `true` or `false`.

Examples:

- `"1990-03-20" <= "2008-04-04"`
- `annual_income_eur >= 50000`
- `country == "Netherlands"`

Each predicate can be represented as:

```
predicate = (claim_index, operator, constant)
```

- `claim_index`: index to the claim value
- `operator`: comparison operator
- `constant`: comparison value

Supported predicate operators:

- `<=`
- `>=`
- `==`

From a theoretical perspective, `<` and `=` are sufficient to construct all comparison operators.

In this design, we include `<=` and `>=` for simplicity and optimization (fewer constraints).

Examples of rewrites:

- `<` can be rewritten as `<= (value - 1)`
- `>` can be rewritten as `>= (value + 1)`
- `!=` can be expressed as `NOT (==)` using logical composition

Restricting the operator set simplifies circuit construction and reduces constraint count.

Each predicate operates on exactly one claim value and compares it against a constant. Relations involving multiple claims can be expressed through logical composition.

## Example Predicate List

Credential reference:

```
claims = {
  date_of_birth: "2003-06-15",
  country: "Germany",
  annual_income_eur: 52000
}
```

Predicate list:

```
P0: date_of_birth <= "2008-04-04"
P1: annual_income_eur >= 50000
P2: country == "Netherlands"
```

Checking against the credential reference:

```
P0: "2003-06-15" <= "2008-04-04" -> true
P1: 52000 >= 50000               -> true
P2: "Germany" == "Netherlands"   -> false
```

After evaluation:

```
P0 → true
P1 → true
P2 → false
```

# 3. Logical Expression

The logical expression combines predicate results using boolean operators.

Supported logical operators:

- AND
- OR
- NOT

From a theoretical perspective, `AND` and `NOT` are functionally complete, so all logical operators can be expressed using only those two.

In this design, `OR` is included explicitly for simplicity and optimization (fewer constraints).

# Why Postfix Notation is Used

Although users naturally write expressions in infix notation, postfix notation is used inside the circuit for several reasons:

1. No parentheses required
2. No operator precedence handling inside circuit
3. Deterministic evaluation order
4. Stack based evaluation
5. No branching logic
6. Reduced circuit complexity

Infix notation requires parsing rules such as:

- precedence handling
- parentheses matching
- recursive evaluation

These operations are inefficient in zero knowledge circuits because they require conditional branching and dynamic control flow.

Postfix notation removes all ambiguity and allows simple linear evaluation.

# Infix and Postfix Examples

Infix:

```
A AND B
```

Postfix:

```
A B AND
```

Complex example:

Infix:

```
(A AND B) OR (C AND D)
```

Postfix:

```
A B AND C D AND OR
```

# Conversion from Infix to Postfix

The conversion from infix to postfix is performed outside the circuit using the Shunting Yard algorithm, adapted to handle logical expressions and operators.

The circuit therefore evaluates only the postfix logical expression over predicate outputs, avoiding parsing and operator precedence handling inside the circuit.

The system assumes the provided postfix expression correctly represents the intended policy. Since the postfix expression is a public input, the verifier can independently validate that it is well formed and corresponds to the expected policy before verifying the proof.

Example conversion:

Infix:

`(date_of_birth <= "2008-04-04" AND annual_income_eur >= 50000) OR country == "Netherlands"`

Postfix:

```
P0 P1 AND P2 OR
```

# Evaluation Flow

The proving process consists of two conceptual steps.

## Step 1: Predicate Evaluation

Claims:

```
date_of_birth = "2003-06-15"
annual_income_eur = 52000
country = "Germany"
```

Predicates:

```
P0: date_of_birth <= "2008-04-04" → true
P1: annual_income_eur >= 50000 → true
P2: country == "Netherlands" → false
```

Predicate results:

```
[ true, true, false ]
```

## Step 2: Logical Expression Evaluation

Policy:

`(date_of_birth <= "2008-04-04" AND annual_income_eur >= 50000) OR country == "Netherlands"`

Postfix:

```
P0 P1 AND P2 OR
```

Evaluation steps (processing the postfix expression from left to right, in a stack based way):

```
1. Read P0   -> push true
2. Read P1   -> push true
3. Read AND  -> pop true, true; push true
4. Read P2   -> push false
5. Read OR   -> pop false, true; push true
```

Final result:

```
true
```

Only the final boolean value is revealed.

# Formal Model

Claims:

$C = (c_0, c_1, \ldots, c_n)$

Predicates:

$P_i = (j_i, \mathsf{op}_i, k_i), \quad i \in \{0, \ldots, m\}, \quad j_i \in \{0, \ldots, n\}, \quad \mathsf{op}_i \in \{\le, \ge, =\}$

where $j_i$ is the claim index, and $k_i$ is the predicate constant.

Predicate evaluation:

$r_i = \mathsf{op}_i(c_{j_i}, k_i) \in \{0,1\}, \quad i \in \{0, \ldots, m\}$

Predicate results:

$R = (r_0, r_1, \ldots, r_m)$

Logical expression (postfix notation):

$L = (\ell_0, \ell_1, \ldots, \ell_t)$

$\ell_q \in \{r \mid r \in R\} \cup \{\mathrm{AND}, \mathrm{OR}, \mathrm{NOT}\}, \quad q \in \{0, \ldots, t\}$

The prover generates a zero knowledge proof that:

$b = E(L), \quad b \in \{0,1\}$

without revealing $C$.

# Privacy Guarantees

The verifier learns:

- Logical expression (policy)
- Predicate constants
- Final boolean result

The verifier does not learn:

- Claim values
- Individual predicate results
- Intermediate evaluation steps

# Derived Predicate Patterns: Range, Membership, and Non Membership

Common predicate patterns such as range checks, membership, and non membership can be expressed through logical composition of basic predicates.

## Range Proofs

Range proofs allow proving that a value lies within an interval.

Example:

`30000 <= annual_income_eur <= 60000`

Predicates:

`P0: annual_income_eur >= 30000`
`P1: annual_income_eur <= 60000`

Logical expression:

```
P0 P1 AND
```

This proves the value lies in the range.

## Membership Proofs

Membership in a set:

$country \in {X, Y, Z}$

Predicates:

`P0: country == X`
`P1: country == Y`
`P2: country == Z`

Logical expression:

```
P0 P1 OR P2 OR
```

This proves the value belongs to the set without revealing which element.

## Non Membership Proofs

Non membership:

$country \notin {X, Y}$

Predicates:

`P0: country == X`
`P1: country == Y`

Logical expression:

```
P0 NOT P1 NOT AND
```

This proves the value is not in the forbidden set.

## Combining Range and Membership

Example policy:

"User is millennial and located in one of these EU countries: NL, BE, or DE"

Using ISO 8601 date-of-birth notation (`YYYY-MM-DD`):

Predicates:

`P0: date_of_birth >= "1981-01-01"`
`P1: date_of_birth <= "1996-12-31"`
`P2: country == NL`
`P3: country == BE`
`P4: country == DE`

Logical expression:

```
P0 P1 AND P2 P3 OR P4 OR AND
```

This proves:

- user is millennial
- user country is one of these EU countries: NL, BE, or DE

without revealing either value.

# Example: Age Verification

This example shows the complete flow for proving adulthood (>= 18) using a date of birth claim.

Note: Today's date for this example is `2026-04-04`. The cutoff date is `2008-04-04`, calculated as today's date minus 18 years.

Given credential:

```
claims = {
  date_of_birth: "1990-03-20"
  // ... other credential claims
}
```

Predicate definition:

```
P0: date_of_birth <= cutoff_date
```

Single-predicate expression (no logical operator needed):

```
P0
```

Evaluation:

```
"1990-03-20" <= "2008-04-04" -> true
```

Result:

```
true
```

This verifies the holder is `>= 18` on `2026-04-04`, without revealing the exact age.

When only one predicate is used, generalized predicates still apply: the expression can be just that predicate token, with no `AND`, `OR`, or `NOT` required.
