// Crypto + data model of the vault. Nothing in this file touches the network.
// Vault data: {items:[{id, site, user, note, mt, pw}], tomb:{id: deletedAtMs}}. Site, user and note are stored as is
// (protected by the Google account and Firestore rules); each password is sealed under its own item Key:
//   pw = {salt, iv, ct}: AES-256-GCM under HKDF(PBKDF2-SHA256(item Key, item salt, 600k)), fresh IV on every seal.
// The item Key is typed on every use and never stored or sent anywhere.
export const ITER = 600000, FORMAT = 4;
const TOMB_TTL = 365 * 24 * 3600 * 1000;
const enc = new TextEncoder(), dec = new TextDecoder();
const AES = {name:'AES-GCM', length:256};

// chunked so large inputs don't blow the call stack
export function b64(buf){
  const u = new Uint8Array(buf); let s = '';
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000));
  return btoa(s);
}
export const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
// version token of a stored copy: changes on every write
export const newVer = () => b64(crypto.getRandomValues(new Uint8Array(12)));

async function itemKeyFrom(pass, salt){
  const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name:'PBKDF2', salt, iterations:ITER, hash:'SHA-256'}, base, 256);
  const hk = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'HKDF', hash:'SHA-256', salt:new Uint8Array(32), info:enc.encode('vault/item/v3')},
    hk, AES, false, ['encrypt','decrypt']);
}
// k = {key, salt} as returned by openItem: re-seal under the same item key (fresh IV — never reuse)
export async function resealItem(k, text){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, k.key, enc.encode(text));
  return {salt: k.salt, iv: b64(iv), ct: b64(ct)};
}
export async function sealItem(pass, text){
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return resealItem({key: await itemKeyFrom(pass, salt), salt: b64(salt)}, text);
}
// throws on a wrong Key (AES-GCM authentication fails)
export async function openItem(pass, pw){
  const key = await itemKeyFrom(pass, unb64(pw.salt));
  const text = dec.decode(await crypto.subtle.decrypt({name:'AES-GCM', iv: unb64(pw.iv)}, key, unb64(pw.ct)));
  return {text, k: {key, salt: pw.salt}};
}

// validate vault data from storage / a backup; returns null when it isn't one
const isPw = p => p === null || (!!p && typeof p.salt === 'string' && typeof p.iv === 'string' && typeof p.ct === 'string');
export function parseData(v){
  if (typeof v === 'string') try { v = JSON.parse(v); } catch { return null; }
  if (!v || !Array.isArray(v.items) || (v.tomb != null && typeof v.tomb !== 'object')) return null;
  const items = v.items.filter(i => i && typeof i.id === 'string' && typeof i.site === 'string' && isPw(i.pw ?? null))
    .map(i => ({id: i.id, site: i.site, user: String(i.user ?? ''), note: String(i.note ?? ''), mt: Number(i.mt) || 0, pw: i.pw ?? null}));
  if (items.length !== v.items.length) return null;
  const tomb = {};
  for (const [id, ms] of Object.entries(v.tomb || {})) if (Number.isFinite(ms)) tomb[id] = ms;
  return {items, tomb};
}

// merge two copies: newest edit (mt) wins per item, with a deterministic tie-break; deletions are kept as tombstones for a year
const itemKey = i => JSON.stringify([i.site ?? '', i.user ?? '', i.note ?? '', i.pw?.ct ?? '']);
export function merge(a, b){
  const now = Date.now(), tomb = {}, out = new Map();
  for (const t of [a.tomb, b.tomb]) for (const [id, ms] of Object.entries(t))
    if (now - ms < TOMB_TTL) tomb[id] = Math.max(tomb[id] || 0, ms);
  for (const it of [...a.items, ...b.items]){
    const cur = out.get(it.id), m = it.mt || 0, cm = cur?.mt || 0;
    if (!cur || m > cm || (m === cm && itemKey(it) > itemKey(cur))) out.set(it.id, it);
  }
  for (const [id, ms] of Object.entries(tomb)){
    const it = out.get(id);
    if (it && (it.mt || 0) <= ms) out.delete(id);
  }
  return {items:[...out.values()], tomb};
}

const canon = d => JSON.stringify([
  [...d.items].sort((x, y) => x.id < y.id ? -1 : x.id > y.id ? 1 : 0).map(i => [i.id, i.mt || 0, itemKey(i)]),
  Object.entries(d.tomb).sort()
]);
export const sameData = (a, b) => canon(a) === canon(b);
