package wallet

// RegistrationSigningPrimary decides which key must SIGN a transaction that
// carries a public key for on-chain registration (incident 2026-09-08).
//
// The consensus rule (Transaction.Verify) accepts a registration only when the
// signature can be verified: either it is made by a key already REGISTERED for
// the sender under the signing slot's current scheme, or — for an identity with
// nothing registered — by the enclosed key itself when that key derives the
// sender's address (self-certifying bootstrap). Signing with the ACTIVE scheme's
// key regardless (the previous `!IsPaused()` rule) produced unverifiable
// combinations the moment that key was not yet registered: the exact
// "signed with MAYO-2 but sender has no registered MAYO-2 key" rejection.
//
// Inputs:
//
//	hasPrimary/hasSecondary — is a key of the CURRENT scheme registered for the
//	                          sender in that slot (the node's PUBA answer);
//	registerPrimary         — which slot the ENCLOSED key belongs to;
//	defaultPrimary          — the non-registration signing default
//	                          (typically !common.IsPaused()).
//
// Rule:
//   - nothing registered  → sign with the enclosed key itself (bootstrap;
//     admitted by Verify's self-registration path even under a pause);
//   - one slot registered → sign with that registered key (it authorizes the
//     new key; admitted under a pause by the stranded-identity path);
//   - both registered     → the default is verifiable; keep it.
func RegistrationSigningPrimary(hasPrimary, hasSecondary, registerPrimary, defaultPrimary bool) bool {
	if !hasPrimary && !hasSecondary {
		return registerPrimary
	}
	if hasPrimary && hasSecondary {
		return defaultPrimary
	}
	return hasPrimary
}
