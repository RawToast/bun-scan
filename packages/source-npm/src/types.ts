/**
 * npm Audit API types
 */

/// <reference types="bun-types" />

/** npm severity levels that map to fatal level */
export type FatalSeverity = "critical" | "high"

/** All npm audit severity levels */
export type NpmSeverity = "critical" | "high" | "moderate" | "low" | "info"
