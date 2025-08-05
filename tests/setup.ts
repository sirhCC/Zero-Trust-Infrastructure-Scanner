/**
 * Test Setup for Zero-Trust Infrastructure Scanner
 */

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'error'; // Reduce noise during tests

// Global test configuration
jest.setTimeout(30000);

// Only mock external dependencies that might not be available in test environment
// Don't mock fs as scanners may need to read files
jest.mock('axios', () => ({
  get: jest.fn(),
  post: jest.fn(),
  put: jest.fn(),
  delete: jest.fn(),
}));

// Mock network requests but allow filesystem access
jest.mock('node-cron', () => ({
  schedule: jest.fn(),
  destroy: jest.fn(),
}));

// Suppress console output during tests (unless testing logging)
const originalConsole = global.console;
global.console = {
  ...originalConsole,
  log: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

// Clean up after all tests
afterAll(() => {
  global.console = originalConsole;
});
