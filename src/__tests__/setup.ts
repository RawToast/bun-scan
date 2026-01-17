/**
 * Test setup - preloaded before all tests via bunfig.toml
 * Sets default log level to suppress noise during test runs
 */
process.env.BUN_SCAN_LOG_LEVEL = "error"
