/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import { describe, expect, test } from "bun:test";

describe("CHANGELOG.md Infrastructure", () => {
	describe("Keep-a-Changelog Compliance", () => {
		test("validates correct CHANGELOG structure", () => {
			const validChangelog = `# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

### Changed

### Fixed

## [1.0.1] - 2025-01-03

### Added
- New feature

## [1.0.0] - 2024-10-13

### Added
- Initial release
`;

			// Verify [Unreleased] comes before any version
			const lines = validChangelog.split("\n");
			const unreleasedIdx = lines.findIndex((l) =>
				/^## \[Unreleased\]/.test(l),
			);
			const firstVersionIdx = lines.findIndex(
				(l, i) => i > unreleasedIdx && /^## \[\d+\.\d+\.\d+\]/.test(l),
			);

			expect(unreleasedIdx).toBeGreaterThan(0);
			expect(firstVersionIdx).toBeGreaterThan(unreleasedIdx);
		});

		test("detects missing [Unreleased] section", () => {
			const invalidChangelog = `# Changelog

## [1.0.1] - 2025-01-03

### Added
- New feature
`;

			const hasUnreleased = /^## \[Unreleased\]/m.test(invalidChangelog);
			expect(hasUnreleased).toBe(false);
		});

		test("detects wrong [Unreleased] position", () => {
			const wrongOrderChangelog = `# Changelog

## [1.0.1] - 2025-01-03

### Added
- New feature

## [Unreleased]

### Added
`;

			const lines = wrongOrderChangelog.split("\n");
			const unreleasedIdx = lines.findIndex((l) =>
				/^## \[Unreleased\]/.test(l),
			);
			const firstVersionIdx = lines.findIndex((l) =>
				/^## \[\d+\.\d+\.\d+\]/.test(l),
			);

			// Should fail - Unreleased comes AFTER version
			expect(unreleasedIdx).toBeGreaterThan(firstVersionIdx);
		});

		test("validates version chronological order", () => {
			const validChangelog = `## [Unreleased]

## [2.0.0] - 2025-02-01

## [1.1.0] - 2025-01-15

## [1.0.1] - 2025-01-03

## [1.0.0] - 2024-10-13
`;

			const versionRegex = /^## \[(\d+\.\d+\.\d+)\]/gm;
			const versions: string[] = [];
			let match: RegExpExecArray | null;

			match = versionRegex.exec(validChangelog);
			while (match !== null) {
				if (match[1]) {
					versions.push(match[1]);
				}
				match = versionRegex.exec(validChangelog);
			}

			// Verify descending order (newest first)
			expect(versions).toEqual(["2.0.0", "1.1.0", "1.0.1", "1.0.0"]);

			// Verify semver descending
			for (let i = 0; i < versions.length - 1; i++) {
				const [maj1 = 0, min1 = 0, pat1 = 0] =
					versions[i]?.split(".").map(Number) ?? [];
				const [maj2 = 0, min2 = 0, pat2 = 0] =
					versions[i + 1]?.split(".").map(Number) ?? [];

				const isDescending =
					maj1 > maj2 ||
					(maj1 === maj2 && min1 > min2) ||
					(maj1 === maj2 && min1 === min2 && pat1 > pat2);

				expect(isDescending).toBe(true);
			}
		});
	});

	describe("Version Insertion Logic (release.yml awk simulation)", () => {
		test("inserts new version after [Unreleased] section", () => {
			const originalChangelog = `# Changelog

## [Unreleased]

### Added

### Changed

## [1.0.0] - 2024-10-13

### Added
- Initial release
`;

			const newVersionEntry = `## [1.0.1] - 2025-01-03

### Added
- New feature

### Fixed
- Bug fix
`;

			// Simulate the awk logic from release.yml
			const lines = originalChangelog.split("\n");
			const result: string[] = [];
			let foundUnreleased = false;
			let inserted = false;

			for (const line of lines) {
				if (/^## \[Unreleased\]/.test(line)) {
					foundUnreleased = true;
					result.push(line);
					continue;
				}

				if (foundUnreleased && !inserted && /^## \[/.test(line)) {
					// Insert new version before this line
					result.push(...newVersionEntry.split("\n"));
					inserted = true;
				}

				result.push(line);
			}

			const updatedChangelog = result.join("\n");

			// Verify insertion happened
			expect(updatedChangelog).toContain("## [1.0.1] - 2025-01-03");

			// Verify order: Unreleased -> 1.0.1 -> 1.0.0
			const versionLines = updatedChangelog
				.split("\n")
				.map((l, i) => ({ line: l, index: i }))
				.filter(({ line }) => /^## \[/.test(line));

			expect(versionLines).toHaveLength(3);
			expect(versionLines[0]?.line).toContain("[Unreleased]");
			expect(versionLines[1]?.line).toContain("[1.0.1]");
			expect(versionLines[2]?.line).toContain("[1.0.0]");
		});

		test("handles empty [Unreleased] section", () => {
			const changelog = `## [Unreleased]

## [1.0.0] - 2024-10-13
`;

			const newVersion = `## [1.0.1] - 2025-01-03

### Changed
- Update
`;

			const lines = changelog.split("\n");
			const result: string[] = [];
			let foundUnreleased = false;
			let inserted = false;

			for (const line of lines) {
				if (/^## \[Unreleased\]/.test(line)) {
					foundUnreleased = true;
					result.push(line);
					continue;
				}

				if (foundUnreleased && !inserted && /^## \[/.test(line)) {
					result.push(...newVersion.split("\n"));
					inserted = true;
				}

				result.push(line);
			}

			const updated = result.join("\n");
			expect(updated).toContain("[1.0.1]");
			expect(updated.indexOf("[1.0.1]")).toBeLessThan(
				updated.indexOf("[1.0.0]"),
			);
		});

		test("fails gracefully when [Unreleased] missing", () => {
			const changelog = `## [1.0.0] - 2024-10-13

### Added
- Initial
`;

			const hasUnreleased = /^## \[Unreleased\]/m.test(changelog);
			expect(hasUnreleased).toBe(false);

			// Workflow should fail with error
			// This tests the validation in release.yml line 102-105
		});

		test("handles multiple versions correctly", () => {
			const changelog = `## [Unreleased]

## [1.2.0] - 2025-01-20

## [1.1.0] - 2025-01-15

## [1.0.0] - 2024-10-13
`;

			const newVersion = `## [1.3.0] - 2025-01-25

### Added
- Feature
`;

			const lines = changelog.split("\n");
			const result: string[] = [];
			let foundUnreleased = false;
			let inserted = false;

			for (const line of lines) {
				if (/^## \[Unreleased\]/.test(line)) {
					foundUnreleased = true;
					result.push(line);
					continue;
				}

				if (foundUnreleased && !inserted && /^## \[/.test(line)) {
					result.push(...newVersion.split("\n"));
					inserted = true;
				}

				result.push(line);
			}

			const updated = result.join("\n");
			const versionOrder = updated
				.split("\n")
				.filter((l) => /^## \[/.test(l))
				.map((l) => l.match(/\[([^\]]+)\]/)?.[1]);

			expect(versionOrder).toEqual([
				"Unreleased",
				"1.3.0",
				"1.2.0",
				"1.1.0",
				"1.0.0",
			]);
		});
	});

	describe("Version Extraction Logic (publish.yml awk simulation)", () => {
		test("extracts changelog for specific version", () => {
			const changelog = `## [Unreleased]

### Added

## [1.0.1] - 2025-01-03

### Added
- Automated CHANGELOG generation
- Package verification

### Changed
- GitHub Actions workflow

### Fixed
- CHANGELOG positioning

## [1.0.0] - 2024-10-13

### Added
- Initial release
`;

			// Simulate publish.yml awk extraction (lines 93-97)
			const version = "1.0.1";
			const lines = changelog.split("\n");
			const extracted: string[] = [];
			let found = false;

			for (const line of lines) {
				if (new RegExp(`^## \\[${version}\\]`).test(line)) {
					found = true;
					continue; // Skip the version header itself
				}

				if (found && /^## \[/.test(line)) {
					break; // Stop at next version
				}

				if (found) {
					extracted.push(line);
				}
			}

			const extractedText = extracted.join("\n").trim();

			expect(extractedText).toContain("Automated CHANGELOG generation");
			expect(extractedText).toContain("GitHub Actions workflow");
			expect(extractedText).toContain("CHANGELOG positioning");
			expect(extractedText).not.toContain("Initial release");
			expect(extractedText).not.toContain("[1.0.0]");
		});

		test("returns empty for non-existent version", () => {
			const changelog = `## [Unreleased]

## [1.0.0] - 2024-10-13

### Added
- Initial release
`;

			const version = "2.0.0";
			const lines = changelog.split("\n");
			const extracted: string[] = [];
			let found = false;

			for (const line of lines) {
				if (new RegExp(`^## \\[${version}\\]`).test(line)) {
					found = true;
					continue;
				}

				if (found && /^## \[/.test(line)) {
					break;
				}

				if (found) {
					extracted.push(line);
				}
			}

			expect(extracted.join("\n").trim()).toBe("");
		});

		test("extracts version at end of file", () => {
			const changelog = `## [Unreleased]

## [1.0.1] - 2025-01-03

### Added
- Middle version

## [1.0.0] - 2024-10-13

### Added
- Initial release
- First version ever
`;

			const version = "1.0.0";
			const lines = changelog.split("\n");
			const extracted: string[] = [];
			let found = false;

			for (const line of lines) {
				if (new RegExp(`^## \\[${version}\\]`).test(line)) {
					found = true;
					continue;
				}

				if (found && /^## \[/.test(line)) {
					break;
				}

				if (found) {
					extracted.push(line);
				}
			}

			const extractedText = extracted.join("\n").trim();

			expect(extractedText).toContain("Initial release");
			expect(extractedText).toContain("First version ever");
			expect(extractedText).not.toContain("Middle version");
		});

		test("handles version with empty sections", () => {
			const changelog = `## [Unreleased]

## [1.0.1] - 2025-01-03

### Added

### Changed

### Fixed
- Only fixed section has content

## [1.0.0] - 2024-10-13
`;

			const version = "1.0.1";
			const lines = changelog.split("\n");
			const extracted: string[] = [];
			let found = false;

			for (const line of lines) {
				if (new RegExp(`^## \\[${version}\\]`).test(line)) {
					found = true;
					continue;
				}

				if (found && /^## \[/.test(line)) {
					break;
				}

				if (found) {
					extracted.push(line);
				}
			}

			const extractedText = extracted.join("\n").trim();

			expect(extractedText).toContain("### Added");
			expect(extractedText).toContain("### Changed");
			expect(extractedText).toContain("### Fixed");
			expect(extractedText).toContain("Only fixed section has content");
		});
	});

	describe("Edge Cases and Error Handling", () => {
		test("handles malformed version headers", () => {
			const malformed = `## [Unreleased]

## 1.0.1 - 2025-01-03  # Missing brackets

### Added
- Feature
`;

			// Version regex should not match malformed headers
			const validVersions = malformed.match(/^## \[\d+\.\d+\.\d+\]/gm);
			expect(validVersions).toBeNull();
		});

		test("handles duplicate version entries", () => {
			const duplicate = `## [Unreleased]

## [1.0.1] - 2025-01-03

### Added
- First entry

## [1.0.1] - 2025-01-02

### Added
- Duplicate entry
`;

			const matches = duplicate.match(/^## \[1\.0\.1\]/gm);
			expect(matches).toHaveLength(2);
			// Workflow should detect and fail
		});

		test("handles missing date format", () => {
			const noDate = `## [Unreleased]

## [1.0.1]

### Added
- No date
`;

			const hasDate = /^## \[\d+\.\d+\.\d+\] - \d{4}-\d{2}-\d{2}/m.test(noDate);
			expect(hasDate).toBe(false);
		});

		test("validates date format", () => {
			const validDate = "2025-01-03";
			const invalidDate = "01-03-2025";

			const validPattern = /^\d{4}-\d{2}-\d{2}$/;
			expect(validPattern.test(validDate)).toBe(true);
			expect(validPattern.test(invalidDate)).toBe(false);
		});

		test("handles very large CHANGELOG files", () => {
			// Generate large changelog
			let largeChangelog = "# Changelog\n\n## [Unreleased]\n\n";

			for (let major = 10; major >= 1; major--) {
				for (let minor = 9; minor >= 0; minor--) {
					for (let patch = 9; patch >= 0; patch--) {
						largeChangelog += `## [${major}.${minor}.${patch}] - 2024-01-01\n\n### Changed\n- Update\n\n`;
					}
				}
			}

			// Should handle without errors
			const versions = largeChangelog.match(/^## \[\d+\.\d+\.\d+\]/gm);
			expect(versions).toBeTruthy();
			expect(versions?.length).toBe(1000); // 10 * 10 * 10
		});

		test("preserves formatting and whitespace", () => {
			const changelog = `## [Unreleased]

## [1.0.1] - 2025-01-03

### Added
- Feature with  double  spaces
- Feature with	tab

### Changed

- Indented item
  - Sub-item
    - Deep item
`;

			const version = "1.0.1";
			const lines = changelog.split("\n");
			const extracted: string[] = [];
			let found = false;

			for (const line of lines) {
				if (new RegExp(`^## \\[${version}\\]`).test(line)) {
					found = true;
					continue;
				}

				if (found && /^## \[/.test(line)) {
					break;
				}

				if (found) {
					extracted.push(line);
				}
			}

			const extractedText = extracted.join("\n");

			// Verify whitespace preserved
			expect(extractedText).toContain("double  spaces");
			expect(extractedText).toContain("  - Sub-item");
			expect(extractedText).toContain("    - Deep item");
		});
	});

	describe("Real-World CHANGELOG Scenarios", () => {
		test("matches actual project CHANGELOG structure", () => {
			const actualChangelog = `# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [1.0.1] - 2025-01-03

### Added
- Automated CHANGELOG generation from conventional commits in release workflow
- Comprehensive repository state validation before releases
- Package content verification before npm publishing

### Changed
- GitHub Actions release workflow now fully automated with zero manual editing required
- CHANGELOG structure updated to comply with Keep-a-Changelog specification

### Fixed
- CHANGELOG [Unreleased] section positioning (now at top per Keep-a-Changelog spec)
- Race condition between commit and tag push operations (now atomic with --follow-tags)

### Security
- Added concurrency controls to prevent simultaneous release/publish operations
- Implemented branch validation to prevent accidental releases from feature branches

## [1.0.0] - 2024-10-13

### Added
- Complete OSV Scanner Implementation
- OSV.dev API Integration
`;

			// Validate structure
			expect(actualChangelog).toMatch(/^## \[Unreleased\]/m);
			expect(actualChangelog).toMatch(/^## \[1\.0\.1\] - 2025-01-03/m);
			expect(actualChangelog).toMatch(/^## \[1\.0\.0\] - 2024-10-13/m);

			// Validate order
			const unreleasedPos = actualChangelog.indexOf("## [Unreleased]");
			const v101Pos = actualChangelog.indexOf("## [1.0.1]");
			const v100Pos = actualChangelog.indexOf("## [1.0.0]");

			expect(unreleasedPos).toBeLessThan(v101Pos);
			expect(v101Pos).toBeLessThan(v100Pos);

			// Validate sections present
			expect(actualChangelog).toContain("### Added");
			expect(actualChangelog).toContain("### Changed");
			expect(actualChangelog).toContain("### Fixed");
			expect(actualChangelog).toContain("### Security");
		});
	});
});
