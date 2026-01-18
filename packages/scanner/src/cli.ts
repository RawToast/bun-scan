import { scanner } from "./index.js"
import { logger } from "@repo/core"

/**
 * CLI interface for testing and debugging the vulnerability scanner
 */

function printUsage() {
  console.log(`
Bun Vulnerability Scanner CLI

Usage:
  bun run src/cli.ts test <package@version> [package@version...]
  bun run src/cli.ts scan <package.json>
  bun run src/cli.ts --help

Commands:
  test      Test scanning specific packages
  scan      Scan packages from a package.json file
  --help    Show this help message

Examples:
  bun run src/cli.ts test lodash@4.17.20 express@4.18.0
  bun run src/cli.ts test event-stream@3.3.6
  bun run src/cli.ts scan ./package.json

Environment Variables:
  BUN_SCAN_LOG_LEVEL  Set logging level (debug, info, warn, error)
  BUN_SCAN_SOURCE     Set vulnerability source (osv, npm, both)
`)
}

function exitWithError(message: string, code: number = 1): never {
  logger.error(message)
  process.exit(code)
}

async function testPackages(packageSpecs: string[]) {
  if (packageSpecs.length === 0) {
    exitWithError("No packages specified for testing")
  }

  const packages: Bun.Security.Package[] = []

  for (const spec of packageSpecs) {
    const match = spec.match(/^(.+)@(.+)$/)
    if (!match) {
      exitWithError(`Invalid package specification: ${spec}. Use format: package@version`)
    }

    const [, name, version] = match
    if (!name || !version) {
      exitWithError(`Invalid package specification: ${spec}`)
    }

    packages.push({
      name,
      version,
      requestedRange: version,
      tarball: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
    })
  }

  logger.info(`Testing ${packages.length} packages:`)
  for (const pkg of packages) {
    logger.info(`  - ${pkg.name}@${pkg.version}`)
  }

  const startTime = Date.now()
  const advisories = await scanner.scan({ packages })
  const duration = Date.now() - startTime

  console.log(`\n📊 Scan Results (completed in ${duration}ms):`)
  console.log(`Packages scanned: ${packages.length}`)
  console.log(`Advisories found: ${advisories.length}\n`)

  if (advisories.length === 0) {
    console.log("✅ No security advisories found - all packages appear safe!")
  } else {
    console.log("🚨 Security advisories:")
    for (const advisory of advisories) {
      const levelIcon = advisory.level === "fatal" ? "🔴" : "⚠️"
      const levelText = advisory.level.toUpperCase()

      console.log(`\n${levelIcon} ${levelText}: ${advisory.package}`)
      if (advisory.description) {
        console.log(`   Description: ${advisory.description}`)
      }
      if (advisory.url) {
        console.log(`   URL: ${advisory.url}`)
      }
    }
  }
}

async function scanPackageJson(packageJsonPath: string) {
  try {
    const file = Bun.file(packageJsonPath)
    if (!(await file.exists())) {
      exitWithError(`Package.json file not found: ${packageJsonPath}`)
    }

    const packageJson = await file.json()
    const dependencies = {
      ...packageJson.dependencies,
      ...packageJson.devDependencies,
      ...packageJson.peerDependencies,
    }

    const packages: Bun.Security.Package[] = []
    for (const [name, versionRange] of Object.entries(dependencies)) {
      // For demo purposes, use the range as the version
      // In reality, you'd need to resolve the actual installed version
      let version = versionRange as string

      // Clean up common version prefixes
      version = version.replace(/^[~^]/, "")

      packages.push({
        name,
        version,
        requestedRange: versionRange as string,
        tarball: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
      })
    }

    logger.info(`Found ${packages.length} dependencies in ${packageJsonPath}`)
    await testPackages(packages.map((p) => `${p.name}@${p.version}`))
  } catch (error) {
    exitWithError(
      `Failed to read package.json: ${error instanceof Error ? error.message : String(error)}`,
    )
  }
}

export async function runCli() {
  const args = process.argv.slice(2)

  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    printUsage()
    return
  }

  const command = args[0]
  const commandArgs = args.slice(1)

  switch (command) {
    case "test": {
      await testPackages(commandArgs)
      break
    }

    case "scan": {
      if (commandArgs.length === 0) {
        exitWithError("No package.json file specified")
      }
      const file = commandArgs[0]
      if (!file) {
        exitWithError("Package.json file path required")
      }
      await scanPackageJson(file)
      break
    }

    default: {
      exitWithError(`Unknown command: ${command}`)
    }
  }
}

// CLI entry point
if (import.meta.main) {
  await runCli()
}
