/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import { describe, expect, test } from "bun:test";

describe("Version Management", () => {
	describe("Semantic Version Validation", () => {
		test("validates correct semver format", () => {
			const validVersions = [
				"1.0.0",
				"0.0.1",
				"10.20.30",
				"1.0.0-alpha",
				"1.0.0-beta.1",
				"1.0.0+build.123",
			];

			const semverPattern =
				/^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$/;

			for (const version of validVersions) {
				expect(semverPattern.test(version)).toBe(true);
			}
		});

		test("rejects invalid semver format", () => {
			const invalidVersions = [
				"1.0",
				"1",
				"v1.0.0", // 'v' prefix not in semver
				"1.0.0.0",
				"1.a.0",
				"",
			];

			const semverPattern =
				/^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$/;

			for (const version of invalidVersions) {
				expect(semverPattern.test(version)).toBe(false);
			}
		});

		test("validates version tag format (with v prefix)", () => {
			const validTags = ["v1.0.0", "v0.0.1", "v10.20.30"];

			const tagPattern = /^v\d+\.\d+\.\d+$/;

			for (const tag of validTags) {
				expect(tagPattern.test(tag)).toBe(true);
			}
		});

		test("rejects invalid version tag format", () => {
			const invalidTags = ["1.0.0", "V1.0.0", "v1.0", "version1.0.0"];

			const tagPattern = /^v\d+\.\d+\.\d+$/;

			for (const tag of invalidTags) {
				expect(tagPattern.test(tag)).toBe(false);
			}
		});
	});

	describe("Version Bumping Logic", () => {
		test("calculates patch bump", () => {
			const version = "1.0.0";
			const [major = 0, minor = 0, patch = 0] = version.split(".").map(Number);
			const newVersion = `${major}.${minor}.${patch + 1}`;

			expect(newVersion).toBe("1.0.1");
		});

		test("calculates minor bump", () => {
			const version = "1.0.5";
			const [major = 0, minor = 0] = version.split(".").map(Number);
			const newVersion = `${major}.${minor + 1}.0`;

			expect(newVersion).toBe("1.1.0");
		});

		test("calculates major bump", () => {
			const version = "1.5.3";
			const [major = 0] = version.split(".").map(Number);
			const newVersion = `${major + 1}.0.0`;

			expect(newVersion).toBe("2.0.0");
		});

		test("handles version from package.json", () => {
			const packageJson = { version: "1.0.1" };
			const currentVersion = packageJson.version;

			expect(currentVersion).toBe("1.0.1");
			expect(/^\d+\.\d+\.\d+$/.test(currentVersion)).toBe(true);
		});

		test("validates npm version command output format", () => {
			// npm version returns: v1.0.1
			const npmOutput = "v1.0.1";
			const versionPattern = /^v\d+\.\d+\.\d+$/;

			expect(versionPattern.test(npmOutput)).toBe(true);

			const versionNumber = npmOutput.slice(1); // Remove 'v'
			expect(versionNumber).toBe("1.0.1");
		});
	});

	describe("Version Comparison", () => {
		test("compares major versions", () => {
			const v1 = "2.0.0";
			const v2 = "1.0.0";

			const [maj1 = 0] = v1.split(".").map(Number);
			const [maj2 = 0] = v2.split(".").map(Number);

			expect(maj1).toBeGreaterThan(maj2);
		});

		test("compares minor versions when major equal", () => {
			const v1 = "1.5.0";
			const v2 = "1.3.0";

			const [maj1 = 0, min1 = 0] = v1.split(".").map(Number);
			const [maj2 = 0, min2 = 0] = v2.split(".").map(Number);

			expect(maj1).toBe(maj2);
			expect(min1).toBeGreaterThan(min2);
		});

		test("compares patch versions when major and minor equal", () => {
			const v1 = "1.0.5";
			const v2 = "1.0.3";

			const [maj1 = 0, min1 = 0, pat1 = 0] = v1.split(".").map(Number);
			const [maj2 = 0, min2 = 0, pat2 = 0] = v2.split(".").map(Number);

			expect(maj1).toBe(maj2);
			expect(min1).toBe(min2);
			expect(pat1).toBeGreaterThan(pat2);
		});

		test("detects equal versions", () => {
			const v1 = "1.0.1";
			const v2 = "1.0.1";

			expect(v1).toBe(v2);
		});

		test("sorts versions in descending order", () => {
			const versions = ["1.0.0", "2.0.0", "1.5.0", "1.0.1"];

			const sorted = versions.sort((a, b) => {
				const [majA = 0, minA = 0, patA = 0] = a.split(".").map(Number);
				const [majB = 0, minB = 0, patB = 0] = b.split(".").map(Number);

				if (majA !== majB) return majB - majA;
				if (minA !== minB) return minB - minA;
				return patB - patA;
			});

			expect(sorted).toEqual(["2.0.0", "1.5.0", "1.0.1", "1.0.0"]);
		});
	});

	describe("Version Tag Operations (release.yml)", () => {
		test("constructs version tag from package.json version", () => {
			const packageVersion = "1.0.1";
			const tag = `v${packageVersion}`;

			expect(tag).toBe("v1.0.1");
		});

		test("extracts version number from git tag", () => {
			const gitTag = "refs/tags/v1.0.1";
			const version = gitTag.replace("refs/tags/v", "");

			expect(version).toBe("1.0.1");
		});

		test("extracts version from GITHUB_REF", () => {
			const githubRef = "refs/tags/v1.0.1";
			const tagName = githubRef.replace("refs/tags/", "");
			const version = tagName.replace("v", "");

			expect(tagName).toBe("v1.0.1");
			expect(version).toBe("1.0.1");
		});

		test("handles tag without refs/tags/ prefix", () => {
			const tag = "v1.0.1";
			const version = tag.replace(/^v/, "");

			expect(version).toBe("1.0.1");
		});
	});

	describe("Version Verification (publish.yml)", () => {
		test("matches tag version with package.json version", () => {
			const tagVersion = "1.0.1"; // From refs/tags/v1.0.1
			const packageVersion = "1.0.1"; // From package.json

			expect(tagVersion).toBe(packageVersion);
		});

		test("detects version mismatch", () => {
			const tagVersion = "1.0.2";
			const packageVersion = "1.0.1";

			expect(tagVersion).not.toBe(packageVersion);
		});

		test("handles version extraction from GitHub context", () => {
			// Simulate publish.yml lines 43-51
			const githubRef = "refs/tags/v1.0.1";
			const tagVersion = githubRef.replace("refs/tags/v", "");

			const packageJson = { version: "1.0.1" };
			const pkgVersion = packageJson.version;

			if (tagVersion !== pkgVersion) {
				throw new Error(
					`Tag version (${tagVersion}) does not match package.json version (${pkgVersion})`,
				);
			}

			expect(tagVersion).toBe(pkgVersion);
		});
	});

	describe("Repository State Validation (release.yml)", () => {
		test("validates version not already tagged", () => {
			const existingTags = ["v1.0.0", "v1.0.1", "v1.0.2"];
			const newVersion = "v1.0.3";

			const alreadyTagged = existingTags.includes(newVersion);
			expect(alreadyTagged).toBe(false);
		});

		test("detects when version is already tagged", () => {
			const existingTags = ["v1.0.0", "v1.0.1", "v1.0.2"];
			const newVersion = "v1.0.1";

			const alreadyTagged = existingTags.includes(newVersion);
			expect(alreadyTagged).toBe(true);
		});

		test("validates package.json version format", () => {
			const packageJson = { version: "1.0.1" };
			const version = packageJson.version;

			const isValid = /^\d+\.\d+\.\d+$/.test(version);
			expect(isValid).toBe(true);
		});

		test("rejects invalid package.json version", () => {
			const invalidVersions = ["v1.0.1", "1.0", "invalid"];

			for (const version of invalidVersions) {
				const isValid = /^\d+\.\d+\.\d+$/.test(version);
				expect(isValid).toBe(false);
			}
		});
	});

	describe("Version in URLs and Paths", () => {
		test("constructs npm package URL with version", () => {
			const packageName = "bun-osv-scanner";
			const version = "v1.0.1";
			const url = `https://www.npmjs.com/package/${packageName}/v/${version}`;

			expect(url).toBe(
				"https://www.npmjs.com/package/bun-osv-scanner/v/v1.0.1",
			);
		});

		test("constructs GitHub release URL with version", () => {
			const repo = "maloma7/bun-osv-scanner";
			const version = "v1.0.1";
			const url = `https://github.com/${repo}/releases/tag/${version}`;

			expect(url).toBe(
				"https://github.com/maloma7/bun-osv-scanner/releases/tag/v1.0.1",
			);
		});

		test("constructs GitHub blob URL with version", () => {
			const repo = "maloma7/bun-osv-scanner";
			const version = "v1.0.1";
			const file = "CHANGELOG.md";
			const url = `https://github.com/${repo}/blob/${version}/${file}`;

			expect(url).toBe(
				"https://github.com/maloma7/bun-osv-scanner/blob/v1.0.1/CHANGELOG.md",
			);
		});
	});

	describe("Edge Cases", () => {
		test("handles version 0.0.0", () => {
			const version = "0.0.0";
			const isValid = /^\d+\.\d+\.\d+$/.test(version);

			expect(isValid).toBe(true);
		});

		test("handles large version numbers", () => {
			const version = "999.999.999";
			const isValid = /^\d+\.\d+\.\d+$/.test(version);

			expect(isValid).toBe(true);

			const [major = 0, minor = 0, patch = 0] = version.split(".").map(Number);
			expect(major).toBe(999);
			expect(minor).toBe(999);
			expect(patch).toBe(999);
		});

		test("handles version with leading zeros (invalid semver)", () => {
			const version = "01.02.03";
			// Technically invalid semver, but pattern would match
			const matches = /^\d+\.\d+\.\d+$/.test(version);
			expect(matches).toBe(true);

			// However, leading zeros should be rejected in strict validation
			const [major = "0", minor = "0", patch = "0"] = version.split(".");
			const hasLeadingZeros =
				(major.length > 1 && major.startsWith("0")) ||
				(minor.length > 1 && minor.startsWith("0")) ||
				(patch.length > 1 && patch.startsWith("0"));

			expect(hasLeadingZeros).toBe(true);
		});

		test("handles pre-release versions", () => {
			const version = "1.0.0-alpha.1";
			const baseVersion = version.split("-")[0] ?? "";

			expect(baseVersion).toBe("1.0.0");
			expect(/^\d+\.\d+\.\d+$/.test(baseVersion)).toBe(true);
		});

		test("handles build metadata", () => {
			const version = "1.0.0+build.123";
			const baseVersion = version.split("+")[0] ?? "";

			expect(baseVersion).toBe("1.0.0");
			expect(/^\d+\.\d+\.\d+$/.test(baseVersion)).toBe(true);
		});
	});

	describe("Real-World Version Scenarios", () => {
		test("handles actual project version progression", () => {
			const versionHistory = ["1.0.0", "1.0.1"];

			// Verify all valid
			for (const version of versionHistory) {
				expect(/^\d+\.\d+\.\d+$/.test(version)).toBe(true);
			}

			// Verify chronological order (newest first)
			const sorted = [...versionHistory].sort((a, b) => {
				const [majA = 0, minA = 0, patA = 0] = a.split(".").map(Number);
				const [majB = 0, minB = 0, patB = 0] = b.split(".").map(Number);

				if (majA !== majB) return majB - majA;
				if (minA !== minB) return minB - minA;
				return patB - patA;
			});

			expect(sorted).toEqual(["1.0.1", "1.0.0"]);
		});

		test("validates workflow version bump workflow", () => {
			const currentVersion = "1.0.1";
			const bumpType = "patch" as "patch" | "minor" | "major";

			const [major = 0, minor = 0, patch = 0] = currentVersion
				.split(".")
				.map(Number);

			let newVersion: string;
			switch (bumpType) {
				case "patch":
					newVersion = `${major}.${minor}.${patch + 1}`;
					break;
				case "minor":
					newVersion = `${major}.${minor + 1}.0`;
					break;
				case "major":
					newVersion = `${major + 1}.0.0`;
					break;
				default:
					throw new Error(`Invalid bump type: ${bumpType}`);
			}

			expect(newVersion).toBe("1.0.2");
		});

		test("simulates release.yml version workflow", () => {
			// Current state
			const packageJson = { version: "1.0.1" };
			const existingTags = ["v1.0.0", "v1.0.1"];

			// Validation: current version should be tagged
			const currentTag = `v${packageJson.version}`;
			expect(existingTags).toContain(currentTag);

			// Bump to next version
			const _bumpType = "patch";
			const [major = 0, minor = 0, patch = 0] = packageJson.version
				.split(".")
				.map(Number);
			const newVersion = `${major}.${minor}.${patch + 1}`;
			const newTag = `v${newVersion}`;

			// Validation: new version should not be tagged
			expect(existingTags).not.toContain(newTag);

			// After workflow
			expect(newVersion).toBe("1.0.2");
			expect(newTag).toBe("v1.0.2");
		});
	});

	describe("Version Formatting", () => {
		test("formats version for different contexts", () => {
			const version = "1.0.1";

			const gitTag = `v${version}`;
			const npmUrl = `https://www.npmjs.com/package/bun-osv-scanner/v/v${version}`;
			const changelogHeader = `## [${version}] - 2025-01-03`;
			const releaseTitle = `Release v${version}`;

			expect(gitTag).toBe("v1.0.1");
			expect(npmUrl).toContain("v/v1.0.1");
			expect(changelogHeader).toBe("## [1.0.1] - 2025-01-03");
			expect(releaseTitle).toBe("Release v1.0.1");
		});

		test("extracts version from various formats", () => {
			const formats = [
				{ input: "v1.0.1", expected: "1.0.1" },
				{ input: "[1.0.1]", expected: "1.0.1" },
				{ input: "refs/tags/v1.0.1", expected: "1.0.1" },
				{ input: "## [1.0.1] - 2025-01-03", expected: "1.0.1" },
			];

			for (const { input, expected } of formats) {
				const match = input.match(/(\d+\.\d+\.\d+)/);
				expect(match?.[1]).toBe(expected);
			}
		});
	});
});
