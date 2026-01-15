/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import { z } from "zod"

// OSV API request schema
export const OSVQuerySchema = z.object({
  commit: z.string().optional(),
  version: z.string().optional(),
  package: z
    .object({
      name: z.string(),
      ecosystem: z.string(),
      purl: z.string().optional(),
    })
    .optional(),
  page_token: z.string().optional(),
})

// OSV affected package schema
export const OSVAffectedSchema = z.object({
  package: z.object({
    name: z.string(),
    ecosystem: z.string(),
    purl: z.string().optional(),
  }),
  ranges: z
    .array(
      z.object({
        type: z.string(),
        repo: z.string().optional(),
        events: z.array(
          z.object({
            introduced: z.string().optional(),
            fixed: z.string().optional(),
            last_affected: z.string().optional(),
          }),
        ),
      }),
    )
    .optional(),
  versions: z.array(z.string()).optional(),
  ecosystem_specific: z.record(z.string(), z.any()).optional(),
  database_specific: z.record(z.string(), z.any()).optional(),
})

// OSV vulnerability schema
export const OSVVulnerabilitySchema = z.object({
  id: z.string(),
  summary: z.string().optional(),
  details: z.string().optional(),
  modified: z.string().optional(),
  published: z.string().optional(),
  withdrawn: z.string().optional(),
  aliases: z.array(z.string()).optional(),
  related: z.array(z.string()).optional(),
  schema_version: z.string().optional(),
  affected: z.array(OSVAffectedSchema).optional(),
  references: z
    .array(
      z.object({
        type: z.string().optional(),
        url: z.string(),
      }),
    )
    .optional(),
  database_specific: z.record(z.string(), z.any()).optional(),
  severity: z
    .array(
      z.object({
        type: z.string(),
        score: z.string(),
      }),
    )
    .optional(),
  ecosystem_specific: z.record(z.string(), z.any()).optional(),
  credits: z
    .array(
      z.object({
        name: z.string(),
        contact: z.array(z.string()).optional(),
        type: z.string().optional(),
      }),
    )
    .optional(),
})

// OSV API response schema
export const OSVResponseSchema = z.object({
  vulns: z.array(OSVVulnerabilitySchema).optional(),
  next_page_token: z.string().optional(),
})

// OSV batch query schemas
export const OSVBatchQuerySchema = z.object({
  queries: z.array(OSVQuerySchema),
})

export const OSVBatchResponseSchema = z.object({
  results: z.array(
    z.object({
      vulns: z
        .array(
          z.object({
            id: z.string(),
            modified: z.string(),
          }),
        )
        .optional(),
      next_page_token: z.string().optional(),
    }),
  ),
})

// Exported types
export type OSVQuery = z.infer<typeof OSVQuerySchema>
export type OSVAffected = z.infer<typeof OSVAffectedSchema>
export type OSVVulnerability = z.infer<typeof OSVVulnerabilitySchema>
export type OSVResponse = z.infer<typeof OSVResponseSchema>
export type OSVBatchQuery = z.infer<typeof OSVBatchQuerySchema>
export type OSVBatchResponse = z.infer<typeof OSVBatchResponseSchema>
export type OSVSeverity = NonNullable<OSVVulnerability["severity"]>[0]
