// Crypto + data model of the vault. Nothing in this file touches the network.
// Blob on disk / in Firestore: {v, iter, salt, iv, ct} (base64).
//
// v3 (two layers): PBKDF2(Master Key, salt, 600k) → 256 bits → HKDF →
//   meta key: seals the payload {items:[{id, site, user, note, mt, pw}], tomb:{id: deletedAtMs}}
//             (this key may be remembered on a device so the list opens without the Master Key)
//   pw key:   seals passwords of items that have no Key of their own (pw = {iv, ct}); never stored
// Items with their own Key: pw = {salt, iv, ct} under PBKDF2(item Key, item salt) — see sealItem/openItem.
// v1/v2 (legacy): the whole vault, passwords in clear, sealed with the PBKDF2 key directly.
export const ITER = 600000, FORMAT = 3;
const TOMB_TTL = 365 * 24 * 3600 * 1000;
const enc = new TextEncoder(), dec = new TextDecoder();
const AES = {name:'AES-GCM', length:256};

// chunked so large vaults don't blow the call stack
export function b64(buf){
  const u = new Uint8Array(buf); let s = '';
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000));
  return btoa(s);
}
export const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function pbkdf2Bits(pass, salt){
  const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveBits']);
  return crypto.subtle.deriveBits({name:'PBKDF2', salt, iterations:ITER, hash:'SHA-256'}, base, 256);
}
// legacy v1/v2 key
async function legacyKey(pass, salt){
  return crypto.subtle.importKey('raw', await pbkdf2Bits(pass, salt), AES, false, ['decrypt']);
}
export async function deriveKeys(pass, salt){
  const hk = await crypto.subtle.importKey('raw', await pbkdf2Bits(pass, salt), 'HKDF', false, ['deriveKey']);
  const sub = info => crypto.subtle.deriveKey({name:'HKDF', hash:'SHA-256', salt:new Uint8Array(32), info:enc.encode(info)},
    hk, AES, false, ['encrypt','decrypt']);
  return {meta: await sub('vault/meta/v3'), pw: await sub('vault/pw/v3')};
}

// Firebase Auth credentials derived from the Master Key alone (fixed app salt, since nothing is known before login).
// Separate HKDF branch from the vault keys, which use the vault's own random salt: knowing these opens nothing.
const LOGIN_SALT = enc.encode('MasterKeyPw/login/v1');
export async function loginCreds(pass){
  const hk = await crypto.subtle.importKey('raw', await pbkdf2Bits(pass, LOGIN_SALT), 'HKDF', false, ['deriveBits']);
  const sub = async (info, n) => new Uint8Array(await crypto.subtle.deriveBits(
    {name:'HKDF', hash:'SHA-256', salt:new Uint8Array(32), info:enc.encode(info)}, hk, n));
  const id = [...await sub('login/id', 128)].map(b => b.toString(16).padStart(2, '0')).join('');
  return {email: id + '@vault.masterkeypw.app', password: b64(await sub('login/pw', 256))};
}

export function isBlob(v){
  return !!v && typeof v === 'object' && typeof v.salt === 'string' && typeof v.iv === 'string' && typeof v.ct === 'string';
}

// fresh random IV on every call — never reuse
async function encrypt(key, text){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, enc.encode(text));
  return {iv:b64(iv), ct:b64(ct)};
}
async function decrypt(key, {iv, ct}){
  return dec.decode(await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(iv)}, key, unb64(ct)));
}

export async function seal(metaKey, salt, data){
  return {v:FORMAT, iter:ITER, salt:b64(salt), ...await encrypt(metaKey, JSON.stringify(data))};
}
export async function unseal(metaKey, blob){
  const d = JSON.parse(await decrypt(metaKey, blob));
  return {items:d.items || [], tomb:d.tomb || {}};
}
export const sealPw = (pwKey, text) => encrypt(pwKey, text);
export const openPw = (pwKey, pw) => decrypt(pwKey, pw);

// Open any blob with the Master Key. Legacy blobs are upgraded to v3 on the fly (`upgraded: true`).
// The iteration count is fixed: refuse anything weaker (or different) instead of silently accepting it.
export async function openVault(pass, blob){
  if (!isBlob(blob) || blob.iter !== ITER) throw new Error('unsupported');
  const salt = unb64(blob.salt), keys = await deriveKeys(pass, salt);
  if ((blob.v || 1) >= 3) return {keys, salt, data: await unseal(keys.meta, blob)};
  const old = JSON.parse(await decrypt(await legacyKey(pass, salt), blob));
  const o = Array.isArray(old) ? {items:old, tomb:{}} : {items:old.items || [], tomb:old.tomb || {}};
  const items = await Promise.all(o.items.map(async ({pass: p, ...rest}) => ({...rest, pw: p ? await sealPw(keys.pw, p) : null})));
  return {keys, salt, data:{items, tomb:o.tomb}, upgraded:true};
}

// Per-item keys: pw = {salt, iv, ct}, sealed under PBKDF2(item Key, item salt, 600k) → HKDF.
// A pw without `salt` predates per-item keys and is sealed under the vault's pw key (i.e. the Master Key).
async function itemKeyFrom(pass, salt){
  const hk = await crypto.subtle.importKey('raw', await pbkdf2Bits(pass, salt), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'HKDF', hash:'SHA-256', salt:new Uint8Array(32), info:enc.encode('vault/item/v3')},
    hk, AES, false, ['encrypt','decrypt']);
}
// k = {key, salt|null} as returned by openItem: re-seal under the same item key (fresh IV)
export async function resealItem(k, text){
  return {...(k.salt ? {salt: k.salt} : {}), ...await encrypt(k.key, text)};
}
export async function sealItem(pass, text){
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return resealItem({key: await itemKeyFrom(pass, salt), salt: b64(salt)}, text);
}
export async function openItem(pass, pw, vaultSalt){
  const key = pw.salt ? await itemKeyFrom(pass, unb64(pw.salt)) : (await deriveKeys(pass, vaultSalt)).pw;
  return {text: await decrypt(key, pw), k: {key, salt: pw.salt || null}};
}

// re-encrypt the Master-Key-sealed passwords from one pw key to another (vault moving to another salt / Master Key);
// passwords with their own item Key don't depend on the vault and stay as they are
export async function rekey(data, fromPw, toPw){
  const items = await Promise.all(data.items.map(async it =>
    it.pw && !it.pw.salt ? {...it, pw: await sealPw(toPw, await openPw(fromPw, it.pw))} : it));
  return {items, tomb:{...data.tomb}};
}

// Per-item last-writer-wins by `mt` (ties broken by content so every device picks the same winner);
// a tombstone beats any version not newer than the deletion.
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
