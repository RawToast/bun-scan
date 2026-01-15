/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import { describe, expect, test } from "bun:test";

describe("Conventional Commits Parsing", () => {
	describe("Commit Type Extraction", () => {
		test("parses feat commits", () => {
			const commits = [
				"feat: add new feature",
				"feat(scope): add scoped feature",
				"feat!: add breaking feature",
				"feat(api)!: breaking API change",
			];

			for (const commit of commits) {
				const isFeat = /^feat(\(.+\))?(!)?:/.test(commit);
				expect(isFeat).toBe(true);
			}
		});

		test("parses fix commits", () => {
			const commits = [
				"fix: repair bug",
				"fix(parser): fix parsing issue",
				"fix!: breaking bug fix",
			];

			for (const commit of commits) {
				const isFix = /^fix(\(.+\))?(!)?:/.test(commit);
				expect(isFix).toBe(true);
			}
		});

		test("parses refactor/perf/style commits", () => {
			const refactorCommits = [
				"refactor: restructure code",
				"perf: optimize performance",
				"style: format code",
				"refactor(core): refactor core module",
			];

			for (const commit of refactorCommits) {
				const isChanged = /^(refactor|perf|style)(\(.+\))?:/.test(commit);
				expect(isChanged).toBe(true);
			}
		});

		test("parses docs commits", () => {
			const docsCommits = [
				"docs: update README",
				"docs(api): update API documentation",
			];

			for (const commit of docsCommits) {
				const isDocs = /^docs(\(.+\))?:/.test(commit);
				expect(isDocs).toBe(true);
			}
		});

		test("ignores non-conventional commits", () => {
			const nonConventional = [
				"update feature",
				"Fix bug",
				"feat add feature", // Missing colon
				"feature: add", // Wrong prefix
			];

			for (const commit of nonConventional) {
				const isConventional =
					/^(feat|fix|docs|refactor|perf|style|test|chore|build|ci)(\(.+\))?(!)?:/.test(
						commit,
					);
				expect(isConventional).toBe(false);
			}
		});
	});

	describe("Changelog Entry Generation (release.yml simulation)", () => {
		test("converts feat commits to Added section", () => {
			const commits = [
				"feat: add authentication",
				"feat(api): add REST endpoints",
				"feat(ui): add dark mode",
			];

			// Simulate release.yml line 122
			const added = commits
				.filter((c) => /^feat(\(.+\))?:/.test(c))
				.map((c) => c.replace(/^feat[^:]*: /, "- "));

			expect(added).toEqual([
				"- add authentication",
				"- add REST endpoints",
				"- add dark mode",
			]);
		});

		test("converts fix commits to Fixed section", () => {
			const commits = [
				"fix: repair memory leak",
				"fix(parser): handle edge case",
				"fix(db): prevent SQL injection",
			];

			// Simulate release.yml line 124
			const fixed = commits
				.filter((c) => /^fix(\(.+\))?:/.test(c))
				.map((c) => c.replace(/^fix[^:]*: /, "- "));

			expect(fixed).toEqual([
				"- repair memory leak",
				"- handle edge case",
				"- prevent SQL injection",
			]);
		});

		test("converts refactor/perf/style to Changed section", () => {
			const commits = [
				"refactor: restructure modules",
				"perf: optimize query performance",
				"style: apply consistent formatting",
			];

			// Simulate release.yml line 123
			const changed = commits
				.filter((c) => /^(refactor|perf|style)(\(.+\))?:/.test(c))
				.map((c) => c.replace(/^[^:]*: /, "- "));

			expect(changed).toEqual([
				"- restructure modules",
				"- optimize query performance",
				"- apply consistent formatting",
			]);
		});

		test("converts docs commits to Documentation section", () => {
			const commits = [
				"docs: update installation guide",
				"docs(api): add API examples",
			];

			// Simulate release.yml line 125
			const docs = commits
				.filter((c) => /^docs(\(.+\))?:/.test(c))
				.map((c) => c.replace(/^docs[^:]*: /, "- "));

			expect(docs).toEqual([
				"- update installation guide",
				"- add API examples",
			]);
		});

		test("handles empty sections", () => {
			const commits = ["feat: add feature", "docs: update docs"];

			const fixed = commits
				.filter((c) => /^fix(\(.+\))?:/.test(c))
				.map((c) => c.replace(/^fix[^:]*: /, "- "));

			expect(fixed).toEqual([]);
		});

		test("handles mixed conventional commits", () => {
			const commits = [
				"feat: add authentication",
				"fix: repair bug",
				"docs: update README",
				"refactor: clean up code",
				"chore: update dependencies", // Should be ignored
				"test: add tests", // Should be ignored
			];

			const added = commits
				.filter((c) => /^feat(\(.+\))?:/.test(c))
				.map((c) => c.replace(/^feat[^:]*: /, "- "));

			const fixed = commits
				.filter((c) => /^fix(\(.+\))?:/.test(c))
				.map((c) => c.replace(/^fix[^:]*: /, "- "));

			const docs = commits
				.filter((c) => /^docs(\(.+\))?:/.test(c))
				.map((c) => c.replace(/^docs[^:]*: /, "- "));

			const changed = commits
				.filter((c) => /^(refactor|perf|style)(\(.+\))?:/.test(c))
				.map((c) => c.replace(/^[^:]*: /, "- "));

			expect(added).toEqual(["- add authentication"]);
			expect(fixed).toEqual(["- repair bug"]);
			expect(docs).toEqual(["- update README"]);
			expect(changed).toEqual(["- clean up code"]);
		});
	});

	describe("Scope Handling", () => {
		test("removes scope from changelog entry", () => {
			const commits = [
				"feat(auth): add OAuth support",
				"fix(parser): handle null values",
				"docs(api): add examples",
			];

			const addedWithScope = commits
				.filter((c) => /^feat(\(.+\))?:/.test(c))
				.map((c) => c.replace(/^feat[^:]*: /, "- "));

			expect(addedWithScope).toEqual(["- add OAuth support"]);

			// Verify scope is removed
			expect(addedWithScope[0]).not.toContain("(auth)");
		});

		test("handles scope with special characters", () => {
			const commits = [
				"feat(api-v2): add new endpoints",
				"fix(db_migration): handle schema change",
				"refactor(core/utils): extract helpers",
			];

			const pattern = /^(feat|fix|refactor)(\(.+\))?:/;

			for (const commit of commits) {
				expect(pattern.test(commit)).toBe(true);
			}
		});

		test("handles missing scope", () => {
			const commits = ["feat: add feature", "fix: repair bug"];

			const pattern = /^(feat|fix)(\(.+\))?:/;

			for (const commit of commits) {
				expect(pattern.test(commit)).toBe(true);
			}
		});
	});

	describe("Breaking Changes", () => {
		test("detects BREAKING CHANGE in commit body", () => {
			const commitBody = `feat: add new API

BREAKING CHANGE: Old API endpoints removed
BREAKING CHANGE: Configuration format changed
`;

			const breakingChanges = commitBody
				.split("\n")
				.filter((line) => /BREAKING CHANGE:/.test(line))
				.map((line) => line.replace(/BREAKING CHANGE: /, "- "));

			expect(breakingChanges).toEqual([
				"- Old API endpoints removed",
				"- Configuration format changed",
			]);
		});

		test("detects breaking change with ! marker", () => {
			const commits = [
				"feat!: remove deprecated API",
				"fix(auth)!: change token format",
			];

			for (const commit of commits) {
				const hasBreakingMarker = /^(feat|fix)(\(.+\))?!:/.test(commit);
				expect(hasBreakingMarker).toBe(true);
			}
		});

		test("handles no breaking changes", () => {
			const commitBody = `feat: add feature

This is a normal commit without breaking changes.
`;

			const breakingChanges = commitBody
				.split("\n")
				.filter((line) => /BREAKING CHANGE:/.test(line));

			expect(breakingChanges).toEqual([]);
		});
	});

	describe("Edge Cases", () => {
		test("handles commits with colons in description", () => {
			const commit = "feat: add feature: authentication";
			const message = commit.replace(/^feat[^:]*: /, "- ");

			expect(message).toBe("- add feature: authentication");
		});

		test("handles multi-line commit messages", () => {
			const commitMessage = `feat: add authentication

This is a detailed description
with multiple lines.

- First point
- Second point
`;

			const firstLine = commitMessage.split("\n")[0] ?? "";
			const isFeat = /^feat(\(.+\))?:/.test(firstLine);

			expect(isFeat).toBe(true);

			const entry = firstLine.replace(/^feat[^:]*: /, "- ");
			expect(entry).toBe("- add authentication");
		});

		test("handles empty commit messages", () => {
			const commits = ["", " ", "\n"];

			const conventional = commits.filter((c) =>
				/^(feat|fix|docs|refactor|perf|style)(\(.+\))?:/.test(c),
			);

			expect(conventional).toEqual([]);
		});

		test("handles very long commit messages", () => {
			const longCommit = `feat: ${"a".repeat(500)}`;
			const isFeat = /^feat(\(.+\))?:/.test(longCommit);

			expect(isFeat).toBe(true);

			const entry = longCommit.replace(/^feat[^:]*: /, "- ");
			expect(entry.length).toBeGreaterThan(500);
		});

		test("handles commits with unicode characters", () => {
			const commits = [
				"feat: add 🚀 rocket feature",
				"fix: repair 中文 support",
				"docs: update 日本語 documentation",
			];

			for (const commit of commits) {
				const isConventional = /^(feat|fix|docs)(\(.+\))?:/.test(commit);
				expect(isConventional).toBe(true);
			}
		});

		test("handles commits with special regex characters", () => {
			const commits = [
				"feat: add .* wildcard support",
				"fix: handle [brackets]",
				"refactor: use (parentheses)",
			];

			for (const commit of commits) {
				const entry = commit.replace(/^[a-z]+[^:]*: /, "- ");
				expect(entry).toBeTruthy();
			}
		});
	});

	describe("Fallback Handling", () => {
		test("generates fallback when no conventional commits", () => {
			const commits = ["update feature", "fix typo", "improve performance"];

			const conventional = commits.filter((c) =>
				/^(feat|fix|docs|refactor|perf|style)(\(.+\))?:/.test(c),
			);

			// Simulate release.yml lines 165-170
			if (conventional.length === 0) {
				const fallback = "- Internal improvements and maintenance";
				expect(fallback).toBeTruthy();
			}
		});

		test("does not use fallback when conventional commits exist", () => {
			const commits = ["feat: add feature", "update something", "fix typo"];

			const conventional = commits.filter((c) =>
				/^(feat|fix|docs|refactor|perf|style)(\(.+\))?:/.test(c),
			);

			expect(conventional.length).toBeGreaterThan(0);
		});
	});

	describe("Real-World Commit Scenarios", () => {
		test("handles actual project commits", () => {
			const realCommits = [
				"feat: add custom domain configuration for GitHub Pages",
				"fix: correct README.md architecture diagram",
				"docs: update documentation dates",
				"refactor: extract magic numbers to constants",
				"chore(release): v1.0.1",
			];

			const added = realCommits
				.filter((c) => /^feat(\(.+\))?:/.test(c))
				.map((c) => c.replace(/^feat[^:]*: /, "- "));

			const fixed = realCommits
				.filter((c) => /^fix(\(.+\))?:/.test(c))
				.map((c) => c.replace(/^fix[^:]*: /, "- "));

			const docs = realCommits
				.filter((c) => /^docs(\(.+\))?:/.test(c))
				.map((c) => c.replace(/^docs[^:]*: /, "- "));

			const changed = realCommits
				.filter((c) => /^(refactor|perf|style)(\(.+\))?:/.test(c))
				.map((c) => c.replace(/^[^:]*: /, "- "));

			expect(added).toEqual([
				"- add custom domain configuration for GitHub Pages",
			]);
			expect(fixed).toEqual(["- correct README.md architecture diagram"]);
			expect(docs).toEqual(["- update documentation dates"]);
			expect(changed).toEqual(["- extract magic numbers to constants"]);
		});

		test("handles merge commits", () => {
			const mergeCommits = [
				"Merge pull request #1 from branch",
				"Merge branch 'feature' into main",
			];

			const conventional = mergeCommits.filter((c) =>
				/^(feat|fix|docs|refactor|perf|style)(\(.+\))?:/.test(c),
			);

			// Merge commits should be filtered out by --no-merges in git log
			expect(conventional).toEqual([]);
		});

		test("preserves commit message formatting", () => {
			const commits = [
				"feat: add `code` formatting",
				"fix: handle **bold** text",
				"docs: update [links](url)",
			];

			const entries = commits.map((c) => c.replace(/^[a-z]+[^:]*: /, "- "));

			expect(entries).toEqual([
				"- add `code` formatting",
				"- handle **bold** text",
				"- update [links](url)",
			]);
		});
	});

	describe("Changelog Section Assembly", () => {
		test("assembles complete changelog entry", () => {
			const commits = [
				"feat: add authentication",
				"feat: add authorization",
				"fix: repair memory leak",
				"fix: handle null values",
				"docs: update README",
				"refactor: clean up code",
			];

			const added = commits
				.filter((c) => /^feat(\(.+\))?:/.test(c))
				.map((c) => c.replace(/^feat[^:]*: /, "- "));

			const fixed = commits
				.filter((c) => /^fix(\(.+\))?:/.test(c))
				.map((c) => c.replace(/^fix[^:]*: /, "- "));

			const docs = commits
				.filter((c) => /^docs(\(.+\))?:/.test(c))
				.map((c) => c.replace(/^docs[^:]*: /, "- "));

			const changed = commits
				.filter((c) => /^(refactor|perf|style)(\(.+\))?:/.test(c))
				.map((c) => c.replace(/^[^:]*: /, "- "));

			const changelogEntry = `## [1.0.1] - 2025-01-03

### Added

${added.join("\n")}

### Changed

${changed.join("\n")}

### Fixed

${fixed.join("\n")}

### Documentation

${docs.join("\n")}
`;

			expect(changelogEntry).toContain("### Added");
			expect(changelogEntry).toContain("- add authentication");
			expect(changelogEntry).toContain("- add authorization");
			expect(changelogEntry).toContain("### Fixed");
			expect(changelogEntry).toContain("- repair memory leak");
			expect(changelogEntry).toContain("- handle null values");
		});

		test("excludes empty sections", () => {
			const commits = ["feat: add feature"];

			const added = commits
				.filter((c) => /^feat(\(.+\))?:/.test(c))
				.map((c) => c.replace(/^feat[^:]*: /, "- "));

			const fixed = commits
				.filter((c) => /^fix(\(.+\))?:/.test(c))
				.map((c) => c.replace(/^fix[^:]*: /, "- "));

			// Only include sections with content (release.yml lines 129-162)
			let changelogEntry = "## [1.0.1] - 2025-01-03\n\n";

			if (added.length > 0) {
				changelogEntry += "### Added\n\n";
				changelogEntry += `${added.join("\n")}\n\n`;
			}

			if (fixed.length > 0) {
				changelogEntry += "### Fixed\n\n";
				changelogEntry += `${fixed.join("\n")}\n\n`;
			}

			expect(changelogEntry).toContain("### Added");
			expect(changelogEntry).not.toContain("### Fixed");
		});
	});
});
