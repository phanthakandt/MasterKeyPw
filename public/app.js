// UI + Firebase sync. Only sealed blobs {v, iter, salt, iv, ct} ever leave this file; the Master Key and plaintext stay in memory.
// Google sign-in says who the user is (so accounts can be monitored and banned); the Master Key, typed once per device, opens the vault.
// Two layers (see vault-core.js): the meta key opens the list and is remembered per device in IndexedDB (non-extractable);
// each password is sealed under its own item Key, typed on every use; derived keys are dropped right after.
import { ITER, b64, unb64, loginCreds, deriveKeys, seal, unseal, sealItem, resealItem, openItem, openVault, rekey, isBlob, merge, sameData } from './vault-core.js';
import { firebaseConfig } from './firebase-config.js';

const FB = 'https://www.gstatic.com/firebasejs/10.14.1/';
const LEGACY = 'vault.v1', RETRY_MS = 20000, REVEAL_MS = 5000, MAX_AUTH_FAILS = 5, MIN_MASTER_KEY = 8;
const NOT_FOUND = new Set(['auth/invalid-credential', 'auth/invalid-login-credentials', 'auth/user-not-found']);
const EMPTY = {items:[], tomb:{}};
const $ = id => document.getElementById(id);

// ---------- state ----------
let user = null, session = null;               // session = {meta, salt} while the list is open
let data = {items:[], tomb:{}};
let base = null;      // iv of the remote version `data` is based on (null = no remote doc)
let dirty = false;    // local changes not yet in Firestore
let replace = false;  // next push overwrites remote without the version check (restore from backup / user chose overwrite)
let rev = 0;          // bumps on every local change, so a push that raced with an edit doesn't clear `dirty`
let lastRemote;       // undefined = unknown, null = no doc, else blob
let pendingRemote = null, keyConflict = null;
let editingId = null, editKey = null, unwatch = null;  // editKey: the item's key, held only while its editor is open
let revealed = new Map(), authFails = 0;               // item id → {text, timer}
let auth, db, fb, fbConfig;

// ---------- local cache (offline copy, per Firebase user) ----------
const mem = {};
const cacheKey = () => 'vault.v1:' + user.uid;
const cache = {
  get(){ try { const v = JSON.parse(localStorage.getItem(cacheKey())); if (v) return v; } catch {} return mem[cacheKey()] ?? null; },
  set(rec){ mem[cacheKey()] = rec; try { localStorage.setItem(cacheKey(), JSON.stringify(rec)); return true; } catch { return false; } }
};
function saveLocal(blob){
  if (!cache.set({blob, base, dirty, replace})) toast('เบราว์เซอร์นี้ไม่ให้บันทึกถาวร กรุณาสำรองข้อมูลไว้');
}
// ---------- older vaults to fold in ----------
// This device's caches from earlier versions, and the account the Master-Key-login version derived from the Key.
// Each one that opens with the typed Master Key is merged into this Google account's vault and removed once that is synced.
async function legacySources(pass){
  const out = [];
  let keys = [];
  try { keys = Object.keys(localStorage).filter(k => (k === LEGACY || k.startsWith(LEGACY + ':')) && k !== cacheKey()); } catch {}
  for (const k of keys){
    let v; try { v = JSON.parse(localStorage.getItem(k)); } catch { continue; }
    const blob = k === LEGACY ? v : v?.blob;
    if (!isBlob(blob)) continue;
    try { out.push({...await openVault(pass, blob), cleanup: async () => { try { localStorage.removeItem(k); } catch {} }}); } catch {}
  }
  try {
    const cred = await loginCreds(pass), la = legacyAuth();
    const lu = (await fb.signInWithEmailAndPassword(la.auth, cred.email, cred.password)).user;
    const lref = fb.doc(la.db, 'users', lu.uid), snap = await fb.getDocFromServer(lref);
    let opened = null;
    if (snap.exists()) try { opened = await openVault(pass, pick(snap.data())); } catch {}
    const cleanup = async () => {
      try { if (snap.exists()) await fb.deleteDoc(lref); await lu.delete(); await deviceKeys.del(lu.uid); } catch (e) { console.warn(e); }
      try { await fb.signOut(la.auth); } catch {}
    };
    if (opened) out.push({...opened, cleanup});
    else if (!snap.exists()) await cleanup();          // an account with no vault holds nothing
    else await fb.signOut(la.auth);
  } catch (e) { if (!NOT_FOUND.has(e?.code)) console.warn(e); }
  return out;
}
// a second Firebase app, signed in only in memory, so the old account never replaces the Google session
let legacy = null;
function legacyAuth(){
  if (!legacy){
    const app = fb.initializeApp(fbConfig, 'legacy');
    legacy = {auth: fb.initializeAuth(app, {persistence: fb.inMemoryPersistence}), db: fb.getFirestore(app)};
  }
  return legacy;
}

// ---------- remembered meta key (IndexedDB keeps CryptoKey objects without exposing their bytes) ----------
const deviceKeys = {
  async run(mode, fn){
    const db = await new Promise((res, rej) => {
      const r = indexedDB.open('vault', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('keys');
      r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
    });
    return new Promise((res, rej) => {
      const tx = db.transaction('keys', mode), req = fn(tx.objectStore('keys'));
      tx.oncomplete = () => { db.close(); res(req.result); };
      tx.onerror = tx.onabort = () => { db.close(); rej(tx.error); };
    });
  },
  get(uid){ return this.run('readonly', s => s.get(uid)).catch(() => null); },
  put(uid, v){ return this.run('readwrite', s => s.put(v, uid)).catch(() => toast('เบราว์เซอร์นี้จำตู้ไม่ได้ ครั้งหน้าต้องใส่ Master Key อีก')); },
  del(uid){ return this.run('readwrite', s => s.delete(uid)).catch(() => {}); },
};
const rememberDevice = () => deviceKeys.put(user.uid, {salt: b64(session.salt), meta: session.meta});

// ---------- Firestore ----------
class Conflict extends Error { constructor(remote){ super('conflict'); this.remote = remote; } }
const ref = () => fb.doc(db, 'users', user.uid);
const pick = d => ({v:d.v, iter:d.iter, salt:d.salt, iv:d.iv, ct:d.ct});

async function fetchRemote(){
  const s = await fb.getDocFromServer(ref());
  return s.exists() ? pick(s.data()) : null;
}
// expect: iv of the version we built on (null = expect no doc); undefined = force overwrite
async function pushRemote(blob, expect){
  await fb.runTransaction(db, async tx => {
    const s = await tx.get(ref());
    const cur = s.exists() ? pick(s.data()) : null;
    if (expect !== undefined && (cur?.iv ?? null) !== expect) throw new Conflict(cur);
    tx.set(ref(), {...blob, updatedAt: fb.serverTimestamp()});
  });
}

function startWatch(){
  stopWatch();
  unwatch = fb.onSnapshot(ref(), snap => {
    if (snap.metadata.hasPendingWrites || snap.metadata.fromCache) return;
    const remote = snap.exists() ? pick(snap.data()) : null;
    if ((remote?.iv ?? null) === base) return;
    pendingRemote = {blob: remote}; sync();
  }, e => setStatus('error', e));
}
function stopWatch(){ if (unwatch){ unwatch(); unwatch = null; } }

// ---------- sync (single-flight: every remote read/merge/write goes through here) ----------
let syncing = null, again = false, retryTimer = null;
function sync(){
  if (syncing){ again = true; return syncing; }
  syncing = (async () => { do { again = false; await syncOnce(); } while (again && session); })()
    .finally(() => { syncing = null; });
  return syncing;
}

async function syncOnce(){
  const s = session; if (!s || !user) return;
  if (keyConflict) return setStatus('conflict');
  if (pendingRemote && !replace){
    const r = pendingRemote.blob; pendingRemote = null;
    await absorb(r);
    if (session !== s || keyConflict) return;
  }
  pendingRemote = null;
  if (!dirty) return setStatus('synced');
  if (!navigator.onLine) return setStatus('offline');
  setStatus('syncing');
  const myRev = rev;
  try {
    const blob = await seal(s.meta, s.salt, data);
    await pushRemote(blob, replace ? undefined : base);
    if (session !== s) return;
    base = blob.iv; lastRemote = blob; replace = false;
    if (rev === myRev){ dirty = false; saveLocal(blob); }
    else { saveLocal(await seal(s.meta, s.salt, data)); again = true; }
    setStatus(dirty ? 'syncing' : 'synced');
  } catch (e){
    if (session !== s) return;
    if (e instanceof Conflict){ await absorb(e.remote); again = true; return; }
    setStatus(navigator.onLine ? 'error' : 'offline', e);
    clearTimeout(retryTimer); retryTimer = setTimeout(sync, RETRY_MS);
  }
}

// bring a newer remote version into memory: merge if we can decrypt it, otherwise stop and ask the user
async function absorb(remote){
  const s = session;
  lastRemote = remote;
  if (!remote){ base = null; dirty = true; return; }   // doc vanished → recreate it from this device
  if (remote.iv === base) return;
  let theirs;
  try {
    if (remote.salt !== b64(s.salt) || remote.iter !== ITER || (remote.v || 1) < 3) throw 0;
    theirs = await unseal(s.meta, remote);
  } catch { if (session === s) showKeyConflict(remote); return; }
  if (session !== s) return;
  const merged = merge(data, theirs);
  const localChanged = !sameData(merged, data), needPush = !sameData(merged, theirs);
  data = merged; base = remote.iv;
  if (needPush){ dirty = true; rev++; saveLocal(await seal(s.meta, s.salt, data)); }
  else { dirty = false; saveLocal(remote); }
  if (localChanged){ render(); toast('อัปเดตรายการจากอุปกรณ์อื่นแล้ว'); }
}

async function persist(){
  dirty = true; rev++;
  saveLocal(await seal(session.meta, session.salt, data));
  sync();
}

const STATUS = {synced:'ซิงก์แล้ว', syncing:'กำลังซิงก์…', offline:'ออฟไลน์', error:'ซิงก์ไม่สำเร็จ', conflict:'รอตัดสินใจ'};
let lastErr = '';
function setStatus(st, err){
  const el = $('syncLabel');
  el.textContent = st === 'offline' && dirty ? 'ออฟไลน์ · รอซิงก์' : STATUS[st];
  el.dataset.state = st;
  if (st !== 'error'){ lastErr = ''; return; }
  console.warn(err);
  if (err?.code === 'permission-denied' && user){ const u = user; isBanned(u.uid).then(b => b && user === u && showBanned()); }
  const msg = err?.code === 'permission-denied'
    ? 'คลาวด์ปฏิเสธการเข้าถึง ตรวจ Firestore Security Rules'
    : 'ซิงก์ไม่สำเร็จ ข้อมูลยังอยู่ในเครื่อง จะลองใหม่อัตโนมัติ';
  if (msg !== lastErr) toast(msg);
  lastErr = msg;
}

// ---------- show/hide toggle next to Key fields (fields marked data-shown start visible) ----------
function setShown(input, shown){
  input.type = shown ? 'text' : 'password';
  input.parentElement.querySelector('[data-peekfor]').textContent = shown ? 'ซ่อน' : 'แสดง';
}
const resetKeyFields = () => document.querySelectorAll('.keyfield input').forEach(i => setShown(i, i.hasAttribute('data-shown')));
document.addEventListener('click', e => {
  const b = e.target.closest('[data-peekfor]'); if (!b) return;
  e.preventDefault();
  const i = b.parentElement.querySelector('input');
  setShown(i, i.type === 'password'); i.focus();
});

// ---------- views ----------
function show(view){
  resetKeyFields();
  for (const v of ['signin','msg','banned','unlock','vault']) $(v + 'View').hidden = view !== v;
  $('topActions').hidden = $('foot').hidden = view !== 'vault';
  $('acct').hidden = !user || view === 'signin';
  if (view === 'unlock') $('unlockKey').focus();
}
function message(title, body, retry){
  $('msgTitle').textContent = title; $('msgBody').textContent = body;
  $('msgActions').hidden = !retry; $('msgRetry').onclick = retry || null;
  show('msg');
}
function clearSession(){
  stopWatch(); clearTimeout(retryTimer);
  for (const r of revealed.values()) clearTimeout(r.timer);
  revealed.clear(); authFails = 0;
  session = null; data = {items:[], tomb:{}}; editingId = null; editKey = null; keyConflict = null; pendingRemote = null;
  $('list').innerHTML = ''; $('editForm').hidden = true; $('cfKey').value = '';
  $('conflictPanel').hidden = true;
}
function resetAccount(u){
  clearSession();
  user = u; lastRemote = undefined; base = null; dirty = false; replace = false;
  $('acctId').textContent = u ? (u.email || u.displayName || 'บัญชี Google') : '';
}
function useRecord(rec){ base = rec.base ?? null; dirty = !!rec.dirty; replace = !!rec.replace; rev = 0; }

// fetch the remote copy and keep it as the local cache unless this device has unsynced changes
async function prepare(){
  const u = user;
  let rec = cache.get();
  try { lastRemote = await fetchRemote(); } catch (e) { console.warn(e); lastRemote = undefined; }
  if (user !== u) return;
  if (lastRemote && (!rec || (!rec.dirty && rec.base !== lastRemote.iv))){
    rec = {blob: lastRemote, base: lastRemote.iv, dirty: false};
    cache.set(rec);
  }
}
// returning visit: open straight to the list when this device remembers the meta key for the current vault
async function enterWithDevice(){
  const u = user, rec = u && cache.get();
  if (!rec || (rec.blob.v || 1) < 3) return false;
  const dk = await deviceKeys.get(u.uid);
  if (!dk || dk.salt !== rec.blob.salt) return false;
  try {
    const d = await unseal(dk.meta, rec.blob);
    if (user !== u) return true;
    session = {meta: dk.meta, salt: unb64(rec.blob.salt)}; data = d; useRecord(rec);
    enterVault();
    return true;
  } catch { return false; }
}
// leave this device's vault: forget its meta key so the next visit needs the Master Key again
async function lock(){
  const uid = user?.uid;
  if (session && !data.items.length) await dropIfEmpty();
  clearSession();
  if (uid) await deviceKeys.del(uid);
}
// sign-out button: lock, then sign out of Google
async function signOutAll(){
  await lock();
  try { await fb.signOut(auth); } catch { toast('ออกจากระบบไม่สำเร็จ'); }
}
// Leaving a vault with no items: remove its doc and the local copy (the Google account stays, so it can still be monitored).
// Nothing is lost — unlocking again just starts a new vault. Checked against the cloud first, and skipped when offline.
async function dropIfEmpty(){
  try {
    if (syncing) await syncing;
    const s = session;
    if (!s || data.items.length || dirty || !navigator.onLine) return false;
    const remote = await fetchRemote();
    if (remote && (remote.salt !== b64(s.salt) || (await unseal(s.meta, remote)).items.length)) return false;
    const uid = user.uid;
    clearSession();                       // stops the watcher and any further pushes
    if (remote) await fb.deleteDoc(ref());
    try { localStorage.removeItem('vault.v1:' + uid); } catch {}
    delete mem['vault.v1:' + uid];
    lastRemote = null; base = null; dirty = false; replace = false;
    toast('ตู้ว่าง ลบออกแล้ว');
    return true;
  } catch (e) { console.warn(e); return false; }
}

// ---------- Google sign-in ----------
function authError(e){
  const c = e?.code || '';
  if (c === 'auth/popup-closed-by-user' || c === 'auth/cancelled-popup-request') return '';
  if (c === 'auth/operation-not-allowed') return 'ยังไม่ได้เปิด Google ใน Firebase Console → Authentication → Sign-in method';
  if (c === 'auth/unauthorized-domain') return 'โดเมนนี้ยังไม่ได้รับอนุญาต เพิ่มใน Firebase Console → Authentication → Settings → Authorized domains';
  if (c === 'auth/user-disabled') return 'บัญชีนี้ถูกระงับ';
  if (c === 'auth/network-request-failed') return 'เชื่อมต่อเครือข่ายไม่ได้ ลองอีกครั้ง';
  return 'เข้าสู่ระบบไม่สำเร็จ (' + (c || e?.message || 'ไม่ทราบสาเหตุ') + ')';
}
$('signInBtn').addEventListener('click', async () => {
  const btn = $('signInBtn'); btn.disabled = true; $('signinErr').textContent = '';
  const provider = new fb.GoogleAuthProvider();
  provider.setCustomParameters({prompt: 'select_account'});
  try { await fb.signInWithPopup(auth, provider); }
  catch (e){
    if (e?.code === 'auth/popup-blocked' || e?.code === 'auth/operation-not-supported-in-this-environment'){
      try { return await fb.signInWithRedirect(auth, provider); } catch (e2){ e = e2; }
    }
    $('signinErr').textContent = authError(e);
  }
  btn.disabled = false;
});
$('signOutBtn').addEventListener('click', signOutAll);
$('bannedSignOut').addEventListener('click', signOutAll);

// an admin bans an account by creating banned/{uid} in Firestore (the rules then refuse its vault)
async function isBanned(uid){
  try { return (await fb.getDocFromServer(fb.doc(db, 'banned', uid))).exists(); } catch { return false; }
}
function showBanned(){ clearSession(); show('banned'); }

// ---------- unlock with the Master Key (once per device) ----------
let creating = false;
function showLocked(){
  if (!user) return show('signin');
  if (!cache.get() && lastRemote === undefined)
    return message('เชื่อมต่อคลาวด์ไม่ได้', 'เครื่องนี้ยังไม่มีสำเนาตู้ และตรวจไม่ได้ว่ามีตู้บนคลาวด์หรือไม่ ตรวจการเชื่อมต่ออินเทอร์เน็ตแล้วลองอีกครั้ง', () => location.reload());
  creating = !cache.get();
  $('unlockTitle').textContent = creating ? 'ตั้ง Master Key' : 'ปลดล็อกตู้บนเครื่องนี้';
  $('unlockHint').textContent = creating
    ? 'บัญชีนี้ยังไม่มีตู้ ตั้ง Master Key แล้วพิมพ์ซ้ำในช่องยืนยัน ถ้าเคยเข้าเว็บนี้ด้วย Master Key มาก่อน ใส่ Key เดิมช่องเดียวพอ ระบบจะย้ายตู้เดิมมาให้'
    : 'ใส่ Master Key ครั้งเดียวต่ออุปกรณ์ ครั้งต่อไปจะเห็นรายการได้เลย';
  $('unlockNew').hidden = !creating;
  $('unlockErr').textContent = '';
  show('unlock');
}
$('unlockForm').addEventListener('submit', async e => {
  e.preventDefault();
  const btn = $('unlockBtn'), err = $('unlockErr'), pass = $('unlockKey').value, pass2 = $('unlockKey2').value;
  if (!pass) return;
  if (creating && pass2 && pass2 !== pass) return err.textContent = 'Key ทั้งสองช่องไม่ตรงกัน ลองพิมพ์ใหม่';
  if (creating && pass2 && pass.length < MIN_MASTER_KEY) return err.textContent = `Master Key ต้องยาวอย่างน้อย ${MIN_MASTER_KEY} ตัวอักษร`;
  btn.disabled = true; btn.textContent = 'กำลังถอดรหัส…'; err.textContent = '';
  try {
    const u = user, sources = await legacySources(pass);
    if (user !== u) return;
    if (creating && !pass2 && !sources.length) return err.textContent = 'ไม่พบตู้เดิมของ Key นี้ ถ้าจะสร้างตู้ใหม่ ให้พิมพ์ Key อีกครั้งในช่องยืนยัน';
    if (!(await unlock(pass, sources))) { err.textContent = 'Master Key ไม่ถูกต้อง ถอดรหัสไม่ได้'; $('unlockKey').select(); return; }
    $('unlockKey').value = $('unlockKey2').value = '';
  } catch (e2){
    console.warn(e2); err.textContent = 'เปิดตู้ไม่สำเร็จ (' + (e2?.code || e2?.message || 'ไม่ทราบสาเหตุ') + ')';
  } finally { btn.disabled = false; btn.textContent = 'ปลดล็อก'; }
});

// open this account's vault (or start one), fold in the older vaults that open with the same Key, then remember the device
async function unlock(pass, sources){
  const rec = cache.get();
  let keys, salt, d, changed = false, upgraded = false;
  if (rec){
    let r;
    try { r = await openVault(pass, rec.blob); } catch { return false; }
    ({keys, salt, data: d} = r); changed = upgraded = !!r.upgraded;
    useRecord(rec);
    // cloud re-keyed elsewhere (same Master Key, other salt) → move our passwords to its salt and merge, while we still have the pass
    if (!replace && lastRemote && lastRemote.salt !== rec.blob.salt){
      try {
        const r2 = await openVault(pass, lastRemote);
        d = merge(await rekey(d, keys.pw, r2.keys.pw), r2.data);
        keys = r2.keys; salt = r2.salt; base = lastRemote.iv; changed = true;
      } catch {}
    }
  } else {
    salt = crypto.getRandomValues(new Uint8Array(16)); keys = await deriveKeys(pass, salt);
    d = {items:[], tomb:{}}; base = lastRemote?.iv ?? null; replace = false; rev = 0; changed = true;
  }
  for (const s of sources){ d = merge(d, await rekey(s.data, s.keys.pw, keys.pw)); changed = true; }
  session = {meta: keys.meta, salt}; data = d;
  await rememberDevice();
  if (changed) await persist();
  enterVault();
  if (sources.length){
    toast('ย้ายตู้เดิมเข้าบัญชี Google แล้ว');
    if (syncing) await syncing;
    if (!dirty) for (const s of sources) await s.cleanup();   // only once the merged vault is safely in the cloud
  } else if (upgraded) toast('ปรับตู้เป็นแบบเข้ารหัส 2 ชั้นแล้ว');
  return true;
}

function enterVault(){ show('vault'); render(); startWatch(); sync(); }

// ---------- Master Key check (delete fallback, key conflict, restore) ----------
// derive from the typed pass + this vault's salt; correct iff the derived meta key opens something sealed with ours
async function checkKey(pass){
  const s = session;
  if (!pass || !s) return null;
  try {
    const keys = await deriveKeys(pass, s.salt);
    await unseal(keys.meta, await seal(s.meta, s.salt, EMPTY));
    return session === s ? keys : null;
  } catch { return null; }
}
function authFailed(){
  if (++authFails < MAX_AUTH_FAILS) return false;
  lock().then(showLocked); toast('ใส่ Key ผิดหลายครั้ง ล็อกตู้แล้ว');
  return true;
}

// ---------- key conflict (cloud sealed under another salt / Key, e.g. by an outdated tab) ----------
let overwriteArmed = false;
function showKeyConflict(remote){
  keyConflict = remote; overwriteArmed = false;
  $('cfOverwriteBtn').textContent = 'เขียนทับคลาวด์ด้วยข้อมูลเครื่องนี้'; $('cfErr').textContent = '';
  $('conflictPanel').hidden = false;
  setStatus('conflict');
}
function closeKeyConflict(){ keyConflict = null; $('conflictPanel').hidden = true; $('cfKey').value = ''; $('cfErr').textContent = ''; }
$('cfMergeForm').addEventListener('submit', async e => {
  e.preventDefault();
  const btn = $('cfMergeBtn'), remote = keyConflict, s = session, pass = $('cfKey').value;
  if (!remote) return;
  btn.disabled = true; btn.textContent = 'กำลังถอดรหัส…'; $('cfErr').textContent = '';
  try {
    const mine = await checkKey(pass);
    if (!mine) return $('cfErr').textContent = 'Master Key ไม่ถูกต้อง';
    let r;
    try { r = await openVault(pass, remote); }
    catch { return $('cfErr').textContent = 'ข้อมูลบนคลาวด์ใช้ Key อื่น รวมไม่ได้ ให้รีเฟรชอุปกรณ์ที่เปิดเว็บรุ่นเก่าค้างไว้ หรือเขียนทับคลาวด์'; }
    if (session !== s || keyConflict !== remote) return;
    data = merge(await rekey(data, mine.pw, r.keys.pw), r.data);
    session = {meta: r.keys.meta, salt: r.salt}; base = remote.iv;
    closeKeyConflict(); render();
    await rememberDevice();
    await persist();
    toast('รวมข้อมูลแล้ว');
  } finally { btn.disabled = false; btn.textContent = 'รวมข้อมูล'; }
});
$('cfOverwriteBtn').addEventListener('click', async () => {
  if (!overwriteArmed){
    overwriteArmed = true;
    $('cfOverwriteBtn').textContent = 'ยืนยัน: ลบข้อมูลบนคลาวด์แล้วใช้ของเครื่องนี้';
    $('cfErr').textContent = 'รายการที่มีเฉพาะบนคลาวด์จะหายไป';
    return;
  }
  closeKeyConflict(); replace = true;
  await persist();
});

// ---------- list ----------
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function render(){
  const items = data.items;
  const q = $('search').value.trim().toLowerCase();
  const list = items.filter(i => !q || i.site.toLowerCase().includes(q) || (i.user||'').toLowerCase().includes(q))
                    .sort((a,b) => a.site.localeCompare(b.site, 'th'));
  $('countLabel').textContent = items.length + ' รายการ';
  if (!items.length){
    $('list').innerHTML = '<div class="empty">ตู้ยังว่างอยู่<br>กด <strong>+ เพิ่มรายการ</strong> เพื่อฝาก username และรหัสผ่านแรก</div>';
    return;
  }
  if (!list.length){ $('list').innerHTML = '<div class="empty">ไม่พบรายการที่ตรงกับคำค้น</div>'; return; }
  $('list').innerHTML = list.map(i => {
    const shown = revealed.get(i.id), none = !i.pw;
    return `
    <article class="item" data-id="${esc(i.id)}">
      <div class="item-head">
        <span class="item-title">${esc(i.site)}</span>
        <span class="row" style="gap:2px;flex-wrap:nowrap">
          <button class="ghost" data-act="edit">แก้ไข</button>
          <button class="ghost" data-act="del">ลบ</button>
        </span>
      </div>
      <div class="fields">
        <button class="chip" data-act="copy" data-f="user" title="คลิกเพื่อคัดลอก username">
          <span class="k">User</span><span class="v">${esc(i.user) || '<span class="muted">—</span>'}</span><span class="c">คัดลอก</span>
        </button>
        <div class="pw-row">
          <button class="chip" data-act="copy" data-f="pass" title="${shown ? 'คลิกเพื่อคัดลอกรหัสผ่าน' : 'ใส่ Key ของรายการนี้เพื่อดูและคัดลอกรหัสผ่าน'}">
            <span class="k">Pass</span><span class="v">${none ? '<span class="muted">—</span>' : shown ? esc(shown.text) : '••••••••••'}</span><span class="c">${none ? '' : shown ? 'คัดลอก' : 'ดูรหัส'}</span>
          </button>
        </div>
      </div>
      ${i.note ? `<div class="item-note">${esc(i.note)}</div>` : ''}
      <form class="confirm auth" data-auth hidden>
        <span data-authlabel style="flex-basis:100%"></span>
        <span class="keyfield"><input type="password" autocomplete="off" placeholder="Key" aria-label="Key" spellcheck="false" autocapitalize="off" autocorrect="off"><button type="button" class="ghost" data-peekfor>แสดง</button></span>
        <button class="primary" type="submit">ยืนยัน</button>
        <button type="button" data-act="authno">ยกเลิก</button>
        <span class="err" data-autherr></span>
      </form>
    </article>`; }).join('');
}
$('search').addEventListener('input', render);

// which Key opens this item: its own, or the Master Key (no password, or an item from before per-item Keys)
const keyName = item => item.pw?.salt ? 'Key ของรายการนี้' : 'Master Key';
const AUTH_LABEL = {
  reveal: item => `ใส่ ${keyName(item)} เพื่อดูรหัสผ่าน`,
  edit: item => `ใส่ ${keyName(item)} เพื่อแก้ไข`,
  del: item => `ใส่ ${item.pw?.salt ? 'Key ของรายการนี้ หรือ Master Key' : 'Master Key'} เพื่อลบ “${item.site}” ถาวร`,
};
function askKey(card, item, then){
  const f = card.querySelector('[data-auth]');
  f.dataset.then = then; f.hidden = false;
  f.querySelector('[data-authlabel]').textContent = AUTH_LABEL[then](item);
  f.querySelector('input').placeholder = then === 'del' ? 'Key' : keyName(item);
  f.querySelector('[type=submit]').className = then === 'del' ? 'danger' : 'primary';
  f.querySelector('[type=submit]').textContent = then === 'del' ? 'ลบเลย' : 'ยืนยัน';
  f.querySelector('[data-autherr]').textContent = '';
  f.querySelector('input').focus();
}
function reveal(id, text){
  conceal(id);
  revealed.set(id, {text, timer: setTimeout(() => { revealed.delete(id); render(); }, REVEAL_MS)});
}
function conceal(id){ clearTimeout(revealed.get(id)?.timer); revealed.delete(id); }

$('list').addEventListener('click', async e => {
  const btn = e.target.closest('[data-act]'); if (!btn) return;
  const card = btn.closest('.item'), item = data.items.find(i => i.id === card.dataset.id);
  if (!item) return render();
  const act = btn.dataset.act;
  if (act === 'copy'){
    const isPass = btn.dataset.f === 'pass';
    if (isPass && item.pw && !revealed.has(item.id)) return askKey(card, item, 'reveal');
    const val = isPass ? revealed.get(item.id)?.text : item.user;
    if (!val) return toast('ช่องนี้ว่างอยู่');
    await copy(val);
    btn.classList.add('copied'); btn.querySelector('.c').textContent = 'คัดลอกแล้ว';
    setTimeout(() => { btn.classList.remove('copied'); btn.querySelector('.c').textContent = 'คัดลอก'; }, 1500);
    toast(isPass ? 'คัดลอกรหัสผ่านแล้ว' : 'คัดลอก username แล้ว');
  }
  if (act === 'edit') askKey(card, item, 'edit');
  if (act === 'del') askKey(card, item, 'del');
  if (act === 'authno') card.querySelector('[data-auth]').hidden = true;
});

$('list').addEventListener('submit', async e => {
  const f = e.target.closest('[data-auth]'); if (!f) return;
  e.preventDefault();
  const id = f.closest('.item').dataset.id, input = f.querySelector('input'), btn = f.querySelector('[type=submit]');
  const label = btn.textContent, pass = input.value, then = f.dataset.then, s = session;
  const item = data.items.find(i => i.id === id); if (!item) return render();
  btn.disabled = true; btn.textContent = 'กำลังตรวจ…';
  let opened = null, ok = false;
  if (item.pw && pass){ try { opened = await openItem(pass, item.pw, s.salt); ok = true; } catch {} }
  // nothing to open (no password), or deleting with the Master Key when the item's own Key is forgotten
  if (!ok && (!item.pw || then === 'del')) ok = !!(await checkKey(pass));
  input.value = ''; btn.disabled = false; btn.textContent = label;
  if (session !== s) return;
  if (!ok){
    if (authFailed()) return;
    f.querySelector('[data-autherr]').textContent = 'Key ไม่ถูกต้อง';
    return input.focus();
  }
  authFails = 0;
  if (then === 'reveal'){ reveal(id, opened.text); render(); }
  if (then === 'edit'){ f.hidden = true; openEditor(item, opened?.text || '', opened?.k || null); }
  if (then === 'del'){
    conceal(id);
    data.items = data.items.filter(i => i.id !== id);
    data.tomb[id] = Date.now();
    await persist(); render(); toast('ลบแล้ว');
  }
});

async function copy(text){
  try { await navigator.clipboard.writeText(text); return; } catch {}
  const t = document.createElement('textarea');
  t.value = text; t.setAttribute('readonly',''); t.style.position='fixed'; t.style.opacity='0';
  document.body.appendChild(t); t.select();
  try { document.execCommand('copy'); } catch {}
  t.remove();
}

// ---------- editor ----------
// editing arrives already unlocked (k = the item's key); a new Key can be set here, otherwise the current one is kept
const MIN_ITEM_KEY = 6;
let editOrigPass = '';
function openEditor(item, pass = '', k = null){
  editingId = item ? item.id : null; editKey = k; editOrigPass = pass;
  $('editTitle').textContent = item ? 'แก้ไขรายการ' : 'เพิ่มรายการ';
  $('fSite').value = item?.site || ''; $('fUser').value = item?.user || '';
  $('fPass').value = pass; $('fNote').value = item?.note || ''; $('fKey').value = $('fKey2').value = '';
  setShown($('fKey'), true); setShown($('fKey2'), true);
  $('fKeyLabel').textContent = k ? 'เปลี่ยน Key ของรายการนี้ (เว้นว่างเพื่อใช้ Key เดิม)' : 'Key ของรายการนี้ (ใช้ดูรหัสผ่าน)';
  $('editErr').textContent = '';
  $('editForm').hidden = false; $('fSite').focus();
}
function closeEditor(){ $('editForm').hidden = true; $('fPass').value = $('fKey').value = $('fKey2').value = ''; editKey = null; editingId = null; editOrigPass = ''; }
$('addBtn').addEventListener('click', () => openEditor(null));
$('cancelBtn').addEventListener('click', closeEditor);
$('genBtn').addEventListener('click', () => {
  // rejection sampling: no modulo bias
  const cs = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_+=?';
  const lim = 256 - 256 % cs.length, out = [];
  while (out.length < 20) for (const x of crypto.getRandomValues(new Uint8Array(32))) if (x < lim && out.length < 20) out.push(cs[x % cs.length]);
  $('fPass').value = out.join('');
});
$('editForm').addEventListener('submit', async e => {
  e.preventDefault();
  const site = $('fSite').value.trim(), pass = $('fPass').value, err = $('editErr');
  if (!site) return err.textContent = 'ใส่ชื่อเว็บหรือแอปก่อนบันทึก';
  const cur = editingId && data.items.find(i => i.id === editingId);
  const newKey = $('fKey').value;
  if (newKey && newKey !== $('fKey2').value) return err.textContent = 'Key ของรายการทั้งสองช่องไม่ตรงกัน';
  if (newKey && newKey.length < MIN_ITEM_KEY) return err.textContent = `Key ของรายการต้องยาวอย่างน้อย ${MIN_ITEM_KEY} ตัวอักษร`;
  let pw = cur?.pw ?? null;
  if (!pass) pw = null;
  else if (newKey){
    const btn = e.submitter; if (btn){ btn.disabled = true; btn.textContent = 'กำลังเข้ารหัส…'; }
    pw = await sealItem(newKey, pass);
    if (btn){ btn.disabled = false; btn.textContent = 'บันทึก'; }
  }
  else if (editKey){ if (pass !== editOrigPass || !pw) pw = await resealItem(editKey, pass); }
  else return err.textContent = 'ตั้ง Key ของรายการนี้ก่อน เพื่อใช้ดูรหัสผ่านภายหลัง';
  const fields = {site, user:$('fUser').value.trim(), note:$('fNote').value.trim(), pw, mt:Date.now()};
  if (cur) Object.assign(cur, fields);
  // also covers an item deleted on another device while this editor was open: its newer mt outlives the tombstone
  else data.items.push({id: editingId || (crypto.randomUUID ? crypto.randomUUID() : String(Date.now()+Math.random())), ...fields});
  if (editingId) conceal(editingId);
  closeEditor();
  await persist(); render(); toast('บันทึกและเข้ารหัสแล้ว');
});

// ---------- backup ----------
$('exportBtn').addEventListener('click', async () => {
  await copy(JSON.stringify(await seal(session.meta, session.salt, data)));
  toast('คัดลอกข้อความสำรองแล้ว นำไปเก็บไว้ในที่ปลอดภัย');
});
// restore = replace the vault with the backup's items, re-encrypted under this account's Master Key (the login depends on it)
let importArmed = false;
function resetImport(){ importArmed = false; $('importBtn').textContent = 'กู้คืนจากข้อความนี้'; }
$('importBox').addEventListener('input', resetImport);
$('importBtn').addEventListener('click', async () => {
  const err = $('importErr'), btn = $('importBtn');
  let v; try { v = JSON.parse($('importBox').value); } catch {}
  if (!isBlob(v)) return err.textContent = 'ข้อความนี้ไม่ใช่ข้อความสำรองของตู้นี้';
  if (v.iter !== ITER) return err.textContent = 'ข้อความสำรองนี้ใช้การตั้งค่าเข้ารหัสที่ไม่รองรับ';
  if (!importArmed){ importArmed = true; btn.textContent = 'ยืนยัน: แทนที่ข้อมูลปัจจุบัน'; err.textContent = 'รายการในตู้และบนคลาวด์จะถูกแทนที่ด้วยข้อมูลสำรอง'; return; }
  const s = session, bkKey = $('importKey').value, curKey = $('importCurKey').value || bkKey;
  btn.disabled = true; err.textContent = 'กำลังถอดรหัส…';
  try {
    let r;
    try { r = await openVault(bkKey, v); } catch { return err.textContent = 'Master Key ของข้อมูลสำรองไม่ถูกต้อง'; }
    const mine = await checkKey(curKey);
    if (!mine){
      $('importCurRow').hidden = false; $('importCurKey').focus();
      return err.textContent = 'ข้อมูลสำรองใช้ Key ต่างจากตู้นี้ ใส่ Master Key ปัจจุบันด้วย';
    }
    if (session !== s) return;
    data = await rekey(r.data, r.keys.pw, mine.pw);
    replace = true;
    for (const id of [...revealed.keys()]) conceal(id);
    $('importBox').value = $('importKey').value = $('importCurKey').value = ''; $('importCurRow').hidden = true;
    resetImport(); err.textContent = '';
    await persist(); render(); toast('กู้คืนแล้ว');
  } finally { btn.disabled = false; }
});

window.addEventListener('online', () => sync());
window.addEventListener('offline', () => session && setStatus('offline'));
document.addEventListener('visibilitychange', () => { if (!document.hidden && dirty) sync(); });

let tt; function toast(msg){
  const t = $('toast'); t.textContent = msg; t.classList.add('show');
  clearTimeout(tt); tt = setTimeout(() => t.classList.remove('show'), 2400);
}

// ---------- boot ----------
async function boot(){
  if (!crypto.subtle || !window.indexedDB) return message('เบราว์เซอร์ไม่รองรับ', 'เบราว์เซอร์นี้ไม่รองรับการเข้ารหัส กรุณาเปิดด้วยเบราว์เซอร์รุ่นใหม่ผ่าน https');
  message('กำลังโหลด…', 'รอสักครู่');
  let config;
  try {
    const [app, authMod, fsMod] = await Promise.all(['firebase-app.js','firebase-auth.js','firebase-firestore.js'].map(f => import(FB + f)));
    fb = {...app, ...authMod, ...fsMod};
    config = firebaseConfig;
    if (!config?.apiKey){
      const r = await fetch('/__/firebase/init.json');
      if (!r.ok) throw new Error('no-config');
      config = await r.json();
    }
  } catch (e) {
    console.warn(e);
    return message('ยังเชื่อม Firebase ไม่ได้',
      e?.message === 'no-config' ? 'ยังไม่ได้ใส่ Firebase config ใน firebase-config.js (ดู README)' : 'โหลด Firebase SDK ไม่ได้ ตรวจการเชื่อมต่ออินเทอร์เน็ต',
      () => location.reload());
  }
  const app = fb.initializeApp(config);
  auth = fb.getAuth(app);
  db = fb.getFirestore(app);
  fbConfig = config;
  fb.getRedirectResult(auth).catch(e => { $('signinErr').textContent = authError(e); });
  fb.onAuthStateChanged(auth, async u => {
    if (u && session && user?.uid === u.uid) return;
    resetAccount(u);
    if (!u) return show('signin');
    // still signed in from the Master-Key-login version: sign out, keeping its local cache so the Google vault can fold it in
    if (!u.providerData.some(p => p.providerId === 'google.com')){ await fb.signOut(auth); return; }
    message('กำลังเปิดตู้…', 'รอสักครู่');
    if (await isBanned(u.uid)) return user === u && showBanned();
    await prepare();
    if (user === u && !(await enterWithDevice())) showLocked();
  });
}
boot();
