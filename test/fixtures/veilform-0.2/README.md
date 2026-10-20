Format fixtures written by the code from before the rename to Veil (branch
`feat/zero-config-setup`, package `veilform`). They must keep decrypting: see
`test/compat.test.ts`. Test-only key material (`fixture.key` = 32 bytes of 0x07, passphrase
`fixture passphrase 1234`); never use it for anything else.
