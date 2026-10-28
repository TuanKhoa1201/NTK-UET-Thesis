import {readScanHistory, removeScanRecord} from './scanData';

const KEY = '22025523-scan-history-v1';
const HIDDEN_KEY = '22025523-hidden-scan-history-v1';
const CACHE_PREFIX = '22025523-live-dataset:';
const MAX = 50;
const KEEP_FIRST = ['startedAt', 'completedAt', 'repoUrl', 'inputMode'];

function readStored() {
  try {
    const list = JSON.parse(window.localStorage.getItem(KEY) || '[]');
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

function readHiddenMap() {
  try {
    const value = JSON.parse(window.localStorage.getItem(HIDDEN_KEY) || '{}');
    return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  } catch {
    return {};
  }
}

const stamp = (record) => Date.parse(record.startedAt || record.savedAt || '') || 0;

export function readHiddenHistory() {
  return Object.values(readHiddenMap()).sort((a, b) => stamp(b) - stamp(a));
}

export function readHistory() {
  const hidden = readHiddenMap();
  const stored = readStored();
  const known = new Set(stored.map((item) => item.scanId));
  const legacy = readScanHistory()
    .filter((item) => item?.scanId && !known.has(item.scanId))
    .map((item) => ({scanId: item.scanId, savedAt: item.savedAt, status: 'COMPLETED', inputMode: 'GITHUB'}));
  return [...stored, ...legacy]
    .filter((item) => item.scanId && !hidden[item.scanId])
    .sort((a, b) => stamp(b) - stamp(a));
}

export function upsertHistory(partial) {
  if (!partial?.scanId || readHiddenMap()[partial.scanId]) return;
  const list = readStored();
  const old = list.find((item) => item.scanId === partial.scanId) || {};
  const defined = Object.fromEntries(Object.entries(partial).filter(([, value]) => value !== undefined && value !== null && value !== ''));
  KEEP_FIRST.forEach((key) => {
    if (old[key]) delete defined[key];
  });
  const next = {savedAt: new Date().toISOString(), ...old, ...defined};
  const records = [next, ...list.filter((item) => item.scanId !== partial.scanId)].slice(0, MAX);
  try {
    window.localStorage.setItem(KEY, JSON.stringify(records));
  } catch {
    /* storage unavailable or full */
  }
}

export function hideHistoryRecord(record) {
  if (!record?.scanId) return;
  const hidden = readHiddenMap();
  hidden[record.scanId] = {...record, hiddenAt: new Date().toISOString()};
  const stored = readStored().filter((item) => item.scanId !== record.scanId);
  try {
    window.localStorage.setItem(HIDDEN_KEY, JSON.stringify(hidden));
    window.localStorage.setItem(KEY, JSON.stringify(stored));
    window.sessionStorage.removeItem(`${CACHE_PREFIX}${record.scanId}`);
    if (window.sessionStorage.getItem('22025523-scan-id') === record.scanId) {
      window.sessionStorage.removeItem('22025523-scan-id');
    }
    removeScanRecord(record.scanId);
  } catch {
    /* Browser history remains non-destructive if storage is unavailable. */
  }
}

export function restoreHistoryRecord(scanId) {
  const hidden = readHiddenMap();
  const record = hidden[scanId];
  if (!record) return;
  delete hidden[scanId];
  const {hiddenAt, ...visibleRecord} = record;
  const records = [visibleRecord, ...readStored().filter((item) => item.scanId !== scanId)].slice(0, MAX);
  try {
    window.localStorage.setItem(HIDDEN_KEY, JSON.stringify(hidden));
    window.localStorage.setItem(KEY, JSON.stringify(records));
  } catch {
    /* storage unavailable */
  }
}

export const pick = (object, keys) => {
  if (!object || typeof object !== 'object') return undefined;
  for (const key of keys) {
    if (typeof object[key] === 'string' && object[key]) return object[key];
  }
  return undefined;
};