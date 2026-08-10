import { afterEach, describe, expect, it, vi } from 'vitest';
import { configureLogger, createLogger } from '../logger.js';

describe('createLogger', () => {
  afterEach(() => {
    // Reset the shared logger so other test files are unaffected.
    configureLogger({ level: 'warn', json: false });
  });

  it('exposes namespaced level methods', () => {
    const log = createLogger('test');
    expect(typeof log.debug).toBe('function');
    expect(typeof log.info).toBe('function');
    expect(typeof log.warn).toBe('function');
    expect(typeof log.error).toBe('function');
  });

  it('emits entries at or above the configured level', () => {
    const sink = vi.fn();
    configureLogger({ level: 'info', sink });
    const log = createLogger('test-ns');
    log.debug('hidden');
    log.info('visible', { field: 1 });
    log.error('boom');
    expect(sink).toHaveBeenCalledTimes(2);
    const [info, error] = sink.mock.calls.map((call) => call[0]);
    expect(info.level).toBe('info');
    expect(info.namespace).toBe('test-ns');
    expect(info.message).toBe('visible');
    expect(info.fields).toEqual({ field: 1 });
    expect(error.level).toBe('error');
    expect(error.message).toBe('boom');
  });

  it('filters levels below the threshold', () => {
    const sink = vi.fn();
    configureLogger({ level: 'warn', sink });
    const log = createLogger('test');
    log.debug('d');
    log.info('i');
    log.warn('w');
    log.error('e');
    expect(sink).toHaveBeenCalledTimes(2);
    expect(sink.mock.calls.map((c) => c[0].level)).toEqual(['warn', 'error']);
  });

  it('timestamps entries with ISO strings', () => {
    const sink = vi.fn();
    configureLogger({ level: 'info', sink });
    createLogger('ns').info('x');
    const entry = sink.mock.calls[0][0];
    expect(new Date(entry.timestamp).toISOString()).toBe(entry.timestamp);
  });

  it('emits JSON-encoded entries in json mode', () => {
    const sink = vi.fn();
    configureLogger({ level: 'info', sink, json: true });
    createLogger('ns').info('msg', { a: 1 });
    const entry = sink.mock.calls[0][0];
    expect(typeof entry.message).toBe('string');
    const parsed = JSON.parse(entry.message);
    expect(parsed.level).toBe('info');
    expect(parsed.namespace).toBe('ns');
    expect(parsed.fields).toEqual({ a: 1 });
  });

  it('tracks the current level', () => {
    configureLogger({ level: 'debug' });
    const log = createLogger('test');
    expect(log).toBeDefined();
  });
});
