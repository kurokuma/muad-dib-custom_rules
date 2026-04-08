const { isPackageLevelThreat, computeGroupScore } = require('./scoring.js');
const { resetAll } = require('./scan-context.js');
const { initialize } = require('./pipeline/initializer.js');
const { execute } = require('./pipeline/executor.js');
const { process: processThreats } = require('./pipeline/processor.js');
const { output } = require('./pipeline/outputter.js');

function withQuietMachineOutput(enabled, fn) {
  if (!enabled) return fn();

  const original = {
    log: console.log,
    warn: console.warn,
    error: console.error,
    stdoutWrite: process.stdout.write,
    stderrWrite: process.stderr.write
  };

  const noop = () => {};
  const silentWrite = (chunk, encoding, callback) => {
    const cb = typeof encoding === 'function' ? encoding : callback;
    if (typeof cb === 'function') cb();
    return true;
  };

  console.log = noop;
  console.warn = noop;
  console.error = noop;
  process.stdout.write = silentWrite;
  process.stderr.write = silentWrite;

  const restore = () => {
    console.log = original.log;
    console.warn = original.warn;
    console.error = original.error;
    process.stdout.write = original.stdoutWrite;
    process.stderr.write = original.stderrWrite;
  };

  return Promise.resolve()
    .then(fn)
    .finally(restore);
}

async function run(targetPath, options = {}) {
  try {
    // Phase 1: Initialization (validate, IOCs, config, Python detection)
    const quietMachineOutput = options.json === true;
    const { pythonDeps, configApplied, configResult, warnings } = await withQuietMachineOutput(quietMachineOutput, () =>
      initialize(targetPath, options)
    );

    // Phase 2: Execute all scanners
    const { threats, scannerErrors } = await withQuietMachineOutput(quietMachineOutput, () =>
      execute(targetPath, options, pythonDeps, warnings)
    );

    // Phase 3: Process threats (sandbox, dedup, compounds, FP reduction, intent, scoring)
    const processed = await withQuietMachineOutput(quietMachineOutput, () =>
      processThreats(threats, targetPath, options, pythonDeps, warnings, scannerErrors)
    );
    const { result } = processed;

    // _capture mode: return result directly without printing (used by diff.js)
    if (options._capture) {
      return result;
    }

    // Phase 4: Output (CLI formatting, webhook, exit code)
    const exitCode = await output(result, options, processed);

    return exitCode;
  } finally {
    // Clear all per-scan mutable state — even on exception
    resetAll();
  }
}

module.exports = { run, isPackageLevelThreat, computeGroupScore };
