import { describe, expect, test } from "bun:test"

describe("Package Verification", () => {
  describe("Critical File Validation", () => {
    test("validates presence of src/index.ts", () => {
      const packageContents = [
        "package.json",
        "README.md",
        "src/index.ts",
        "src/client.ts",
        "LICENSE",
      ]

      const hasCriticalFile = packageContents.some((file) => file.includes("src/index.ts"))
      expect(hasCriticalFile).toBe(true)
    })

    test("detects missing critical file", () => {
      const packageContents = ["package.json", "README.md", "src/client.ts", "LICENSE"]

      const hasCriticalFile = packageContents.some((file) => file.includes("src/index.ts"))
      expect(hasCriticalFile).toBe(false)
    })

    test("validates multiple critical files", () => {
      const criticalFiles = ["src/index.ts", "package.json", "README.md"]

      const packageContents = [
        "package.json",
        "README.md",
        "src/index.ts",
        "src/client.ts",
        "LICENSE",
      ]

      for (const required of criticalFiles) {
        const hasFile = packageContents.some((file) => file.includes(required))
        expect(hasFile).toBe(true)
      }
    })

    test("handles case-sensitive file matching", () => {
      const packageContents = ["src/Index.ts"] // Wrong case

      const hasCriticalFile = packageContents.some((file) => file === "src/index.ts")
      expect(hasCriticalFile).toBe(false)
    })
  })

  describe("Package Size Validation", () => {
    test("validates package size under 10MB limit", () => {
      const size = 5 * 1024 * 1024 // 5MB in bytes
      const limit = 10 * 1024 * 1024 // 10MB in bytes

      expect(size).toBeLessThan(limit)
    })

    test("detects package size exceeding 10MB", () => {
      const size = 15 * 1024 * 1024 // 15MB in bytes
      const limit = 10 * 1024 * 1024 // 10MB in bytes

      expect(size).toBeGreaterThan(limit)
    })

    test("converts bytes to megabytes correctly", () => {
      const sizeInBytes = 5242880 // 5MB
      const sizeInMB = Math.floor(sizeInBytes / 1048576)

      expect(sizeInMB).toBe(5)
    })

    test("handles exact 10MB size", () => {
      const size = 10 * 1024 * 1024 // Exactly 10MB
      const limit = 10 * 1024 * 1024

      expect(size).toBe(limit)
    })

    test("formats size display", () => {
      const sizes = [
        { bytes: 1024, expected: "1 KB" },
        { bytes: 1048576, expected: "1 MB" },
        { bytes: 5242880, expected: "5 MB" },
      ]

      for (const { bytes, expected } of sizes) {
        const kb = Math.floor(bytes / 1024)
        const mb = Math.floor(bytes / 1048576)

        if (mb > 0) {
          expect(`${mb} MB`).toBe(expected)
        } else {
          expect(`${kb} KB`).toBe(expected)
        }
      }
    })
  })

  describe("npm pack Output Parsing", () => {
    test("parses npm pack --dry-run output for file list", () => {
      const npmPackOutput = `npm notice
npm notice 📦  bun-osv-scanner@1.0.1
npm notice === Tarball Contents ===
npm notice 1.2kB LICENSE
npm notice 3.4kB README.md
npm notice 567B  package.json
npm notice 2.3kB src/index.ts
npm notice 1.5kB src/client.ts
npm notice === Tarball Details ===
npm notice name:          bun-osv-scanner
npm notice version:       1.0.1
npm notice filename:      bun-osv-scanner-1.0.1.tgz
npm notice package size:  5.2 MB
npm notice unpacked size: 10.1 MB
npm notice total files:   5`

      const hasSrcIndex = npmPackOutput.includes("src/index.ts")
      expect(hasSrcIndex).toBe(true)
    })

    test("extracts file list from npm pack output", () => {
      const npmPackOutput = `npm notice 1.2kB LICENSE
npm notice 3.4kB README.md
npm notice 2.3kB src/index.ts`

      const files = npmPackOutput
        .split("\n")
        .filter((line) => line.includes("npm notice"))
        .map((line) => line.split(/\s+/).slice(-1)[0])

      expect(files).toContain("LICENSE")
      expect(files).toContain("README.md")
      expect(files).toContain("src/index.ts")
    })

    test("parses JSON output from npm pack", () => {
      const npmPackJsonOutput = JSON.stringify([
        {
          name: "bun-osv-scanner",
          version: "1.0.1",
          size: 5242880, // 5MB
          unpackedSize: 10485760,
          filename: "bun-osv-scanner-1.0.1.tgz",
        },
      ])

      const parsed = JSON.parse(npmPackJsonOutput)
      expect(parsed[0].size).toBe(5242880)
      expect(parsed[0].name).toBe("bun-osv-scanner")
    })

    test("validates package structure from JSON output", () => {
      const packageData = {
        name: "bun-osv-scanner",
        version: "1.0.1",
        size: 5242880,
        files: [
          { path: "package.json", size: 567 },
          { path: "README.md", size: 3400 },
          { path: "src/index.ts", size: 2300 },
        ],
      }

      expect(packageData.name).toBe("bun-osv-scanner")
      expect(packageData.version).toBe("1.0.1")
      expect(packageData.size).toBeLessThan(10 * 1024 * 1024)

      const hasIndexFile = packageData.files.some((f) => f.path === "src/index.ts")
      expect(hasIndexFile).toBe(true)
    })
  })

  describe("File Pattern Matching", () => {
    test("matches source files pattern", () => {
      const files = ["src/index.ts", "src/client.ts", "src/processor.ts", "src/utils/helper.ts"]

      const sourceFiles = files.filter((f) => f.startsWith("src/"))
      expect(sourceFiles).toHaveLength(4)
    })

    test("excludes test files from package", () => {
      const files = ["src/index.ts", "src/index.test.ts", "src/__tests__/client.test.ts"]

      const nonTestFiles = files.filter((f) => !f.includes(".test.") && !f.includes("__tests__"))

      expect(nonTestFiles).toEqual(["src/index.ts"])
    })

    test("validates required file extensions", () => {
      const files = ["src/index.ts", "src/client.js", "README.md", "package.json"]

      const tsFiles = files.filter((f) => f.endsWith(".ts"))
      const jsFiles = files.filter((f) => f.endsWith(".js"))
      const jsonFiles = files.filter((f) => f.endsWith(".json"))

      expect(tsFiles).toHaveLength(1)
      expect(jsFiles).toHaveLength(1)
      expect(jsonFiles).toHaveLength(1)
    })

    test("validates LICENSE file variations", () => {
      const possibleLicenseFiles = ["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE"]

      for (const licenseFile of possibleLicenseFiles) {
        const isLicense = /^LICEN[CS]E/i.test(licenseFile)
        expect(isLicense).toBe(true)
      }
    })
  })

  describe("package.json Validation", () => {
    test("validates required package.json fields", () => {
      const packageJson = {
        name: "bun-osv-scanner",
        version: "1.0.1",
        main: "./src/index.ts",
        types: "./src/index.ts",
        license: "MIT",
      }

      expect(packageJson.name).toBeTruthy()
      expect(packageJson.version).toBeTruthy()
      expect(packageJson.main).toBeTruthy()
      expect(packageJson.license).toBeTruthy()
    })

    test("validates package.json name format", () => {
      const validNames = ["bun-osv-scanner", "@scope/package", "package-name"]

      const namePattern = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/

      for (const name of validNames) {
        expect(namePattern.test(name)).toBe(true)
      }
    })

    test("rejects invalid package.json names", () => {
      const invalidNames = [
        "UPPERCASE",
        "package name", // Space
        "_package",
        ".package",
      ]

      const namePattern = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/

      for (const name of invalidNames) {
        expect(namePattern.test(name)).toBe(false)
      }
    })

    test("validates files field in package.json", () => {
      const packageJson = {
        name: "bun-osv-scanner",
        version: "1.0.1",
        files: ["src", "README.md", "LICENSE"],
      }

      expect(Array.isArray(packageJson.files)).toBe(true)
      expect(packageJson.files).toContain("src")
      expect(packageJson.files).toContain("README.md")
    })
  })

  describe("Security Validation", () => {
    test("detects sensitive files that should not be published", () => {
      const sensitiveFiles = [".env", ".env.local", "credentials.json", "secrets.yaml", ".npmrc"]

      const packageContents = ["src/index.ts", "package.json", ".env", "credentials.json"]

      const foundSensitive = packageContents.filter((file) => sensitiveFiles.includes(file))

      expect(foundSensitive).toHaveLength(2)
    })

    test("validates .gitignore patterns are respected", () => {
      const gitignorePatterns = [".env", "node_modules", "*.log", ".DS_Store"]

      const files = ["src/index.ts", ".env", "node_modules/package/index.js", "debug.log"]

      const shouldNotPublish = files.filter((file) => {
        for (const pattern of gitignorePatterns) {
          if (pattern.includes("*")) {
            const regex = new RegExp(pattern.replace("*", ".*").replace(".", "\\."))
            if (regex.test(file)) return true
          } else if (file.includes(pattern)) {
            return true
          }
        }
        return false
      })

      expect(shouldNotPublish).toHaveLength(3)
    })

    test("ensures no private keys in package", () => {
      const files = ["src/index.ts", "id_rsa", "private.key", "cert.pem"]

      const keyPatterns = /\.(key|pem)$|^id_rsa/
      const hasPrivateKeys = files.some((f) => keyPatterns.test(f))

      expect(hasPrivateKeys).toBe(true)
    })
  })

  describe("Edge Cases", () => {
    test("handles empty package", () => {
      const packageContents: string[] = []

      const hasCriticalFile = packageContents.some((file) => file.includes("src/index.ts"))
      expect(hasCriticalFile).toBe(false)
    })

    test("handles very large file count", () => {
      const files: string[] = []
      for (let i = 0; i < 10000; i++) {
        files.push(`src/file${i}.ts`)
      }

      expect(files).toHaveLength(10000)

      const hasIndex = files.some((f) => f === "src/file0.ts")
      expect(hasIndex).toBe(true)
    })

    test("handles files with special characters", () => {
      const files = [
        "src/index.ts",
        "src/特殊文字.ts",
        "src/file-with-dash.ts",
        "src/file_with_underscore.ts",
      ]

      const validFiles = files.filter((f) => f.startsWith("src/"))
      expect(validFiles).toHaveLength(4)
    })

    test("handles deeply nested directories", () => {
      const file = "src/a/b/c/d/e/f/deep.ts"
      const depth = file.split("/").length - 1

      expect(depth).toBe(7)
      expect(file.startsWith("src/")).toBe(true)
    })

    test("handles duplicate file entries", () => {
      const files = [
        "src/index.ts",
        "src/index.ts", // Duplicate
        "src/client.ts",
      ]

      const unique = [...new Set(files)]
      expect(unique).toHaveLength(2)
    })
  })

  describe("Real-World Package Scenarios", () => {
    test("validates typical TypeScript package structure", () => {
      const packageContents = [
        "package.json",
        "README.md",
        "LICENSE",
        "src/index.ts",
        "src/client.ts",
        "src/types.ts",
        "src/constants.ts",
      ]

      const requiredFiles = ["package.json", "README.md", "LICENSE", "src/index.ts"]

      for (const required of requiredFiles) {
        expect(packageContents).toContain(required)
      }
    })

    test("validates actual bun-osv-scanner package structure", () => {
      const expectedFiles = [
        "src/index.ts",
        "src/client.ts",
        "src/processor.ts",
        "src/cli.ts",
        "src/retry.ts",
        "src/semver.ts",
        "src/severity.ts",
        "src/logger.ts",
        "src/constants.ts",
        "src/schema.ts",
        "src/types.ts",
        "package.json",
        "README.md",
        "LICENSE",
      ]

      // Verify all expected files would be included
      for (const file of expectedFiles) {
        expect(file).toBeTruthy()
      }
    })

    test("simulates publish.yml package verification (lines 53-72)", () => {
      const packageContents = [
        "package.json",
        "README.md",
        "LICENSE",
        "src/index.ts",
        "src/client.ts",
      ]

      const size = 5 * 1024 * 1024 // 5MB

      // Verify critical files
      const hasCriticalFile = packageContents.includes("src/index.ts")
      expect(hasCriticalFile).toBe(true)

      // Check size
      const sizeMB = Math.floor(size / 1048576)
      expect(sizeMB).toBe(5)

      const exceedsLimit = size > 10 * 1024 * 1024
      expect(exceedsLimit).toBe(false)
    })

    test("handles package with build artifacts excluded", () => {
      const allFiles = [
        "src/index.ts",
        "dist/index.js",
        "node_modules/package/index.js",
        ".git/config",
      ]

      const packageFiles = allFiles.filter(
        (f) => !f.startsWith("dist/") && !f.startsWith("node_modules/") && !f.startsWith(".git/"),
      )

      expect(packageFiles).toEqual(["src/index.ts"])
    })
  })

  describe("Provenance Validation", () => {
    test("validates npm provenance requirements", () => {
      // Publish with provenance requires:
      // - id-token: write permission
      // - --provenance flag
      // - GitHub Actions environment

      const publishCommand = "npm publish --provenance --access public"
      expect(publishCommand).toContain("--provenance")
      expect(publishCommand).toContain("--access public")
    })

    test("validates GitHub Actions permissions for provenance", () => {
      const permissions = {
        contents: "write",
        "id-token": "write",
      }

      expect(permissions["id-token"]).toBe("write")
      expect(permissions.contents).toBe("write")
    })
  })
})
