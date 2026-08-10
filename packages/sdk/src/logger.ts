/**
 * Structured logging for the Stellar Privacy Layer SDK.
 *
 * Design goals:
 * - Level-based filtering (debug < info < warn < error).
 * - Namespaced loggers (`createLogger('client')`).
 * - Structured fields so entries can be shipped to observability backends.
 * - Pluggable sink (defaults to console) and optional JSON output.
 * - Safe in browsers and Node.js (no Node built-ins).
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  namespace: string;
  message: string;
  fields?: Record<string, unknown>;
}

export type LogSink = (entry: LogEntry) => void;

function resolveEnv(name: string): string | undefined {
  // Guarded so the SDK works in browsers where `process` is undefined.
  if (typeof process !== 'undefined' && typeof process.env !== 'undefined') {
    return process.env[name];
  }
  return undefined;
}

function defaultLevel(): LogLevel {
  const fromEnv = resolveEnv('SDK_LOG_LEVEL');
  if (fromEnv && fromEnv in LEVEL_ORDER) {
    return fromEnv as LogLevel;
  }
  return 'warn';
}

class Logger {
  private level: LogLevel = defaultLevel();
  private sink: LogSink = (entry: LogEntry) => {
    const line = `[${entry.timestamp}] ${entry.level.toUpperCase()} ${entry.namespace}: ${entry.message}`;
    if (entry.level === 'error') {
      console.error(line, entry.fields ?? '');
    } else if (entry.level === 'warn') {
      console.warn(line, entry.fields ?? '');
    } else {
      console.log(line, entry.fields ?? '');
    }
  };
  private jsonMode = resolveEnv('SDK_LOG_JSON') === '1';

  setLevel(level: LogLevel): void {
    this.level = level;
  }

  getLevel(): LogLevel {
    return this.level;
  }

  setSink(sink: LogSink): void {
    this.sink = sink;
  }

  setJsonMode(enabled: boolean): void {
    this.jsonMode = enabled;
  }

  log(level: LogLevel, namespace: string, message: string, fields?: Record<string, unknown>): void {
    if (LEVEL_ORDER[level] < LEVEL_ORDER[this.level]) {
      return;
    }
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      namespace,
      message,
      fields,
    };
    if (this.jsonMode) {
      this.sink({ ...entry, message: JSON.stringify(entry) });
    } else {
      this.sink(entry);
    }
  }
}

const rootLogger = new Logger();

/** Configure the global SDK logger. */
export function configureLogger(options: {
  level?: LogLevel;
  sink?: LogSink;
  json?: boolean;
}): void {
  if (options.level) rootLogger.setLevel(options.level);
  if (options.sink) rootLogger.setSink(options.sink);
  if (options.json !== undefined) rootLogger.setJsonMode(options.json);
}

/**
 * Create a namespaced logger, e.g. `createLogger('ShieldedPoolClient')`.
 */
export function createLogger(namespace: string): {
  debug: (message: string, fields?: Record<string, unknown>) => void;
  info: (message: string, fields?: Record<string, unknown>) => void;
  warn: (message: string, fields?: Record<string, unknown>) => void;
  error: (message: string, fields?: Record<string, unknown>) => void;
} {
  return {
    debug: (message, fields) => rootLogger.log('debug', namespace, message, fields),
    info: (message, fields) => rootLogger.log('info', namespace, message, fields),
    warn: (message, fields) => rootLogger.log('warn', namespace, message, fields),
    error: (message, fields) => rootLogger.log('error', namespace, message, fields),
  };
}
