// Crypto + data model of the vault. Nothing in this file touches the network.
// Blob on disk / in Firestore: {v, iter, salt, iv, ct} (base64). Payload inside ct: {items:[...], tomb:{id: deletedAtMs}}.
export const ITER = 600000, FORMAT = 2;
const TOMB_TTL = 365 * 24 * 3600 * 1000;
const enc = new TextEncoder(), dec = new TextDecoder();

// chunked so large vaults don't blow the call stack
export function b64(buf){
  const u = new Uint8Array(buf); let s = '';
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000));
  return btoa(s);
}
export const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

export async function deriveKey(pass, salt){
  const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2', salt, iterations:ITER, hash:'SHA-256'},
    base, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
}

export function isBlob(v){
  return !!v && typeof v === 'object' && typeof v.salt === 'string' && typeof v.iv === 'string' && typeof v.ct === 'string';
}

// fresh random IV on every call — never reuse
export async function seal(key, salt, data){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, enc.encode(JSON.stringify(data)));
  return {v:FORMAT, iter:ITER, salt:b64(salt), iv:b64(iv), ct:b64(ct)};
}

export async function unseal(key, blob){
  const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(blob.iv)}, key, unb64(blob.ct));
  const d = JSON.parse(dec.decode(pt));
  // v1 payload was a bare array of items
  return Array.isArray(d) ? {items:d, tomb:{}} : {items:d.items || [], tomb:d.tomb || {}};
}

// iteration count is fixed: refuse anything weaker (or different) instead of silently accepting it
export async function openBlob(pass, blob){
  if (!isBlob(blob) || blob.iter !== ITER) throw new Error('unsupported');
  const salt = unb64(blob.salt);
  const key = await deriveKey(pass, salt);
  return {key, salt, data: await unseal(key, blob)};
}

// Per-item last-writer-wins by `mt`; a tombstone beats any version not newer than the deletion.
export function merge(a, b){
  const now = Date.now(), tomb = {}, out = new Map();
  for (const t of [a.tomb, b.tomb]) for (const [id, ms] of Object.entries(t))
    if (now - ms < TOMB_TTL) tomb[id] = Math.max(tomb[id] || 0, ms);
  for (const it of [...a.items, ...b.items]){
    const cur = out.get(it.id);
    if (!cur || (it.mt || 0) > (cur.mt || 0)) out.set(it.id, it);
  }
  for (const [id, ms] of Object.entries(tomb)){
    const it = out.get(id);
    if (it && (it.mt || 0) <= ms) out.delete(id);
  }
  return {items:[...out.values()], tomb};
}

const canon = d => JSON.stringify([
  [...d.items].sort((x, y) => x.id < y.id ? -1 : x.id > y.id ? 1 : 0)
    .map(i => [i.id, i.mt || 0, i.site ?? '', i.user ?? '', i.pass ?? '', i.note ?? '']),
  Object.entries(d.tomb).sort()
]);
export const sameData = (a, b) => canon(a) === canon(b);
