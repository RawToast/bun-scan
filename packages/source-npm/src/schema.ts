/**
 * npm Audit API Schemas
 * Fixed for actual npm bulk API response format
 */

import { z } from "zod"

/**
 * npm Audit Bulk Request Schema
 * Format: { "package-name": ["version1", "version2"], ... }
 */
export const NpmAuditRequestSchema = z.record(z.string(), z.array(z.string()))

/**
 * npm Advisory Schema
 * Represents a single security advisory from npm registry
 */
export const NpmAdvisorySchema = z.object({
  /** Advisory ID (e.g., "GHSA-xxxx-xxxx-xxxx" or numeric ID) */
  id: z.union([z.string(), z.number()]),

  /** Advisory title/name */
  title: z.string(),

  /** Package name */
  name: z.string().optional(),

  /** Module name (deprecated, use name) */
  module_name: z.string().optional(),

  /** Severity level */
  severity: z.enum(["critical", "high", "moderate", "low", "info"]),

  /** Vulnerable version ranges */
  vulnerable_versions: z.string(),

  /** Patched versions */
  patched_versions: z.string().optional(),

  /** Advisory URL */
  url: z.string(),

  /** Detailed overview */
  overview: z.string().optional(),

  /** Recommendation */
  recommendation: z.string().optional(),

  /** References */
  references: z.string().optional(),

  /** Access (e.g., "public", "private") */
  access: z.string().optional(),

  /** CWE(s) */
  cwe: z.union([z.string(), z.array(z.string())]).optional(),

  /** CVE(s) */
  cves: z.array(z.string()).optional(),

  /** CVSS score - vectorString can be null */
  cvss: z
    .object({
      score: z.number(),
      vectorString: z.string().nullable().optional(),
    })
    .optional(),

  /** Affected package versions */
  findings: z
    .array(
      z.object({
        version: z.string(),
        paths: z.array(z.string()),
      }),
    )
    .optional(),

  /** Creation time */
  created: z.string().optional(),

  /** Update time */
  updated: z.string().optional(),

  /** Deleted flag */
  deleted: z.boolean().optional(),

  /** GitHub Advisory ID */
  github_advisory_id: z.string().optional(),
})

/**
 * npm Audit Bulk Response Schema
 * FIX: The response is a record of package name -> advisory array
 * NOT advisory ID -> advisory object as incorrectly assumed before
 */
export const NpmAuditResponseSchema = z.record(z.string(), z.array(NpmAdvisorySchema))

// Exported types
export type NpmAuditRequest = z.infer<typeof NpmAuditRequestSchema>
export type NpmAdvisory = z.infer<typeof NpmAdvisorySchema>
export type NpmAuditResponse = z.infer<typeof NpmAuditResponseSchema>
