# Implementation Divergences from `tcgtpm`

## Command Set (`CMD`)

### `D-CMD-1` -- Omitted optional commands [DESIGN] [UNIMPL]

- **Spec**: Optional commands may be omitted; unimplemented commands return `TPM_RC_COMMAND_CODE` (Part 3 §5.2).
- **tcgtpm**: Implements all of the commands below (`TPM2_FieldUpgrade*` and `TPM2_FirmwareRead` are disabled by default).
- **tpm-rs**: Omits:
  - `TPM2_CertifyX509`: avoids in-TPM X.509 / DER handling.
  - `TPM2_SetCapability`: `TPMU_SET_CAPABILITIES` is undefined in Part 2.
  - `TPM2_FieldUpgradeStart`, `TPM2_FieldUpgradeData`, `TPM2_FirmwareRead`: firmware is updated out of band.
  - `TPM2_AC_GetCapability`, `TPM2_AC_Send`, `TPM2_Policy_AC_SendSelect`: Attached Components are not modeled.

---

## Sessions (`SESS`)

### `D-SESS-1` -- Saved context format [DESIGN]

- **Spec**: The `contextBlob` format is vendor-defined (Part 1 §27.1).
- **tcgtpm**: Encrypts raw C `OBJECT` / `SESSION` structs.
- **tpm-rs**: Encrypts a deterministic, endian-independent serialization. `TPM_PT_MAX_OBJECT_CONTEXT` and `TPM_PT_MAX_SESSION_CONTEXT` report its size bounds.

---

## Objects (`OBJ`)

### `D-OBJ-3` -- RSA private key storage format [DESIGN]

- **Spec**: `TPM2B_PRIVATE_KEY_RSA` (Part 2 §11.2.4.8) is sized to hold either the prime `p` or a 5-component CRT key.
- **tcgtpm**: Stores `p` and recomputes `d` on every load.
- **tpm-rs**: Stores the CRT form under `fixedTPM` parents. Accepts either form on load and rejects inconsistent CRT components with `TPM_RC_BINDING`.
