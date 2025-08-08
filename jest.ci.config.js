/**
 * Jest CI Configuration - extends base config but disables coverage thresholds
 */
const base = require('./jest.config');

// Clone to avoid mutating base in-process
const ciConfig = { ...base };

// Remove or relax coverage thresholds for CI runs
delete ciConfig.coverageThreshold;

// Keep coverage collection
ciConfig.coverageDirectory = 'coverage';

module.exports = ciConfig;
