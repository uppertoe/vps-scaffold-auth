## What changes

<!-- One or two sentences. -->

## Security chain

Answer for any change to the gateway, the guard snippets or the deploy files.
The register is [docs/security-assumptions.md](../docs/security-assumptions.md).

- [ ] **Assumptions touched:** <!-- e.g. C3, G4, or "none" -->. Each is still enforced, and the register names its proof.
- [ ] **Newly permitted:** <!-- what does this now allow that was refused before? "nothing" is an answer -->
- [ ] **New surface:** any new token, cookie, header, route or setting has a row in the register.
- [ ] **Tests seen to fail:** each new test failed with the code it protects broken, then passed.
- [ ] `scripts/e2e.sh` passes locally, or the change cannot affect the chain.
