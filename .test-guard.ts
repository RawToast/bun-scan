// .test-guard.ts
import { spawnSync } from "bun"
import { resolve } from "node:path"

const cwd = process.cwd()
const rootDir = resolve(__dirname)

// Check if we're running from the monorepo root
const isMonorepoRoot = cwd === rootDir

if (isMonorepoRoot) {
  console.log("\n💡 Detected 'bun test' from monorepo root")
  console.log("🚀 Running 'turbo run test' instead...\n")

  const result = spawnSync({
    cmd: ["turbo", "run", "test"],
    stdio: ["inherit", "inherit", "inherit"],
    cwd: rootDir,
  })

  // eslint-disable-next-line no-process-exit
  process.exit(result.exitCode ?? 0)
}

// If we're in a package directory, continue with normal test execution
