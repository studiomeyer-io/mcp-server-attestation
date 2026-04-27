/**
 * Attestation error types. All errors thrown by this library are instances of
 * AttestationError so callers can do a single `instanceof` check.
 */

export type AttestationErrorCode =
  | "MANIFEST_PARSE_ERROR"
  | "MANIFEST_SCHEMA_INVALID"
  | "SIGNATURE_INVALID"
  | "SIGNATURE_MISSING"
  | "PUBLIC_KEY_MISMATCH"
  | "TOOL_NOT_IN_MANIFEST"
  | "SPAWN_COMMAND_NOT_ALLOWED"
  | "ARGUMENT_FORBIDDEN_CHAR"
  | "ARGUMENT_RULE_MISMATCH"
  | "ARGUMENT_LENGTH_EXCEEDED"
  | "TRUST_PIN_MISMATCH"
  | "TRUST_FILE_PARSE_ERROR"
  | "KEY_FORMAT_INVALID";

export class AttestationError extends Error {
  public readonly code: AttestationErrorCode;
  public readonly details: Record<string, unknown>;

  constructor(
    code: AttestationErrorCode,
    message: string,
    details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "AttestationError";
    this.code = code;
    this.details = details;
  }
}
