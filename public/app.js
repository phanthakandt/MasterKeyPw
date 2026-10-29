// UI + Firebase sync. Only sealed blobs {v, iter, salt, iv, ct} ever leave this file; the Master Key and plaintext stay in memory.
// Two layers (see vault-core.js): the meta key opens the list and is remembered per device in IndexedDB (non-extractable);
// each password needs the Master Key typed again, and the derived password key is dropped right after use.
import { ITER, b64, unb64, deriveKeys, seal, unseal, sealPw, openPw, openVault, rekey, isBlob, merge, sameData } from './vault-core.js';
import { firebaseConfig } from './firebase-config.js';

const FB = 'https://www.gstatic.com/firebasejs/10.14.1/';
const LEGACY = 'vault.v1', RETRY_MS = 20000, REVEAL_MS = 5000, MAX_AUTH_FAILS = 5;
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
let editingId = null, editPw = null, unwatch = null;   // editPw: password key held only while the editor is open
let revealed = new Map(), authFails = 0;               // item id → {text, timer}
let auth, db, fb;

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
// vault from the pre-Firebase single-file version
function takeLegacy(){
  let v; try { v = JSON.parse(localStorage.getItem(LEGACY)); } catch {}
  return isBlob(v) ? v : null;
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
    try { localStorage.removeItem(LEGACY); } catch {}
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
  const msg = err?.code === 'permission-denied'
    ? 'คลาวด์ปฏิเสธการเข้าถึง ตรวจ Firestore Security Rules'
    : 'ซิงก์ไม่สำเร็จ ข้อมูลยังอยู่ในเครื่อง จะลองใหม่อัตโนมัติ';
  if (msg !== lastErr) toast(msg);
  lastErr = msg;
}

// ---------- views ----------
function show(view){
  for (const v of ['signin','msg','setup','unlock','vault']) $(v + 'View').hidden = view !== v;
  $('topActions').hidden = $('foot').hidden = view !== 'vault';
  $('acct').hidden = !user || view === 'signin';
  if (view === 'setup') $('setKey').focus();
  if (view === 'unlock') $('unlockKey').focus();
}
function message(title, body, retry){
  $('msgTitle').textContent = title; $('msgBody').textContent = body;
  $('msgActions').hidden = !retry; $('msgRetry').onclick = retry || null;
  show('msg');
}
function showLocked(){
  if (!user) return show('signin');
  if (cache.get()) return show('unlock');
  if (lastRemote === null) return show('setup');
  message('เชื่อมต่อคลาวด์ไม่ได้', 'เครื่องนี้ยังไม่มีสำเนาตู้ และตรวจไม่ได้ว่ามีตู้บนคลาวด์หรือไม่ ตรวจการเชื่อมต่ออินเทอร์เน็ตแล้วลองอีกครั้ง', prepare);
}
function clearSession(){
  stopWatch(); clearTimeout(retryTimer);
  for (const r of revealed.values()) clearTimeout(r.timer);
  revealed.clear(); authFails = 0;
  session = null; data = {items:[], tomb:{}}; editingId = null; editPw = null; keyConflict = null; pendingRemote = null;
  $('list').innerHTML = ''; $('editForm').hidden = true; $('unlockKey').value = ''; $('cfKey').value = ''; $('cfKey2').value = '';
  $('conflictPanel').hidden = true;
}
function useRecord(rec){ base = rec.base ?? null; dirty = !!rec.dirty; replace = !!rec.replace; rev = 0; }

// open straight to the list when this device remembers the meta key for the current vault
async function enter(){
  const u = user, rec = u && cache.get();
  if (rec && (rec.blob.v || 1) >= 3){
    const dk = await deviceKeys.get(u.uid);
    if (dk && dk.salt === rec.blob.salt){
      try {
        const d = await unseal(dk.meta, rec.blob);
        if (user !== u) return;
        session = {meta: dk.meta, salt: unb64(rec.blob.salt)}; data = d; useRecord(rec);
        return enterVault();
      } catch {}
    }
  }
  if (user === u) showLocked();
}
// make this device forget the vault: next visit needs the Master Key
async function forget(){
  const uid = user?.uid;
  clearSession();
  if (uid) await deviceKeys.del(uid);
  showLocked();
}

// after sign-in: pick the freshest copy (remote unless this device has unsynced changes)
async function prepare(){
  message('กำลังตรวจสอบตู้บนคลาวด์…', 'รอสักครู่');
  const u = user;
  let rec = cache.get();
  if (!rec){
    const lg = takeLegacy();
    if (lg){ rec = {blob: lg, base: null, dirty: true}; cache.set(rec); }
  }
  try { lastRemote = await fetchRemote(); } catch (e) { console.warn(e); lastRemote = undefined; }
  if (user !== u) return;
  if (lastRemote && (!rec || (!rec.dirty && rec.base !== lastRemote.iv))){
    rec = {blob: lastRemote, base: lastRemote.iv, dirty: false};
    cache.set(rec);
  }
  enter();
}

// ---------- auth ----------
function authError(e){
  const c = e?.code || '';
  if (c === 'auth/popup-closed-by-user' || c === 'auth/cancelled-popup-request') return '';
  if (c === 'auth/unauthorized-domain') return 'โดเมนนี้ยังไม่ได้รับอนุญาต เพิ่มใน Firebase Console → Authentication → Settings → Authorized domains';
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
$('signOutBtn').addEventListener('click', async () => {
  const uid = user?.uid;
  clearSession();
  if (uid) await deviceKeys.del(uid);
  try { await fb.signOut(auth); } catch { toast('ออกจากระบบไม่สำเร็จ'); }
});

// ---------- setup ----------
function strength(p){
  let s = 0;
  if (p.length >= 8) s++; if (p.length >= 12) s++; if (p.length >= 16) s++;
  if (/[a-z]/.test(p) && /[A-Z]/.test(p)) s++; if (/\d/.test(p)) s++; if (/[^A-Za-z0-9]/.test(p)) s++;
  return Math.min(s, 5);
}
$('setKey').addEventListener('input', e => {
  const s = strength(e.target.value), bar = $('meterBar');
  bar.style.width = (s/5*100)+'%';
  bar.style.background = s <= 2 ? 'var(--danger)' : s <= 3 ? 'var(--brass)' : 'var(--ok)';
});
$('setupBtn').addEventListener('click', async () => {
  const a = $('setKey').value, b = $('setKey2').value, err = $('setupErr');
  if (a.length < 8) return err.textContent = 'Key ต้องยาวอย่างน้อย 8 ตัวอักษร';
  if (a !== b) return err.textContent = 'Key ทั้งสองช่องไม่ตรงกัน ลองพิมพ์ใหม่';
  err.textContent = ''; $('setupBtn').disabled = true; $('setupBtn').textContent = 'กำลังสร้าง…';
  const salt = crypto.getRandomValues(new Uint8Array(16));
  session = {meta: (await deriveKeys(a, salt)).meta, salt};
  data = {items:[], tomb:{}}; base = lastRemote?.iv ?? null; replace = false; rev = 0;
  await rememberDevice();
  await persist();
  $('setKey').value = $('setKey2').value = '';
  $('setupBtn').disabled = false; $('setupBtn').textContent = 'สร้างตู้นิรภัย';
  enterVault();
});

// ---------- unlock (once per device) ----------
$('unlockForm').addEventListener('submit', async e => {
  e.preventDefault();
  const btn = $('unlockBtn'), err = $('unlockErr'), rec = cache.get();
  if (!rec) return showLocked();
  btn.disabled = true; btn.textContent = 'กำลังถอดรหัส…'; err.textContent = '';
  const pass = $('unlockKey').value;
  try {
    const r = await openVault(pass, rec.blob);
    let {keys, salt, data: d} = r, changed = !!r.upgraded;
    useRecord(rec);
    // cloud re-keyed elsewhere but with the same Master Key → move our passwords to its salt and merge, while we still have the pass
    if (!replace && lastRemote && lastRemote.salt !== rec.blob.salt){
      try {
        const r2 = await openVault(pass, lastRemote);
        d = merge(await rekey(d, keys.pw, r2.keys.pw), r2.data);
        keys = r2.keys; salt = r2.salt; base = lastRemote.iv; changed = true;
      } catch {}
    }
    session = {meta: keys.meta, salt}; data = d;
    $('unlockKey').value = '';
    await rememberDevice();
    if (changed) await persist();
    enterVault();
    if (r.upgraded) toast('ปรับตู้เป็นแบบเข้ารหัส 2 ชั้นแล้ว');
  } catch {
    err.textContent = 'Key ไม่ถูกต้อง ถอดรหัสไม่ได้';
    $('unlockKey').select();
  }
  btn.disabled = false; btn.textContent = 'ปลดล็อก';
});

function enterVault(){ show('vault'); render(); startWatch(); sync(); }

// ---------- Master Key check for reveal / edit / delete ----------
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
  forget(); toast('ใส่ Key ผิดหลายครั้ง เครื่องนี้ลืมตู้แล้ว ต้องใส่ Master Key ใหม่');
  return true;
}

// ---------- key conflict ----------
let overwriteArmed = false;
function showKeyConflict(remote){
  keyConflict = remote; overwriteArmed = false;
  $('cfOverwriteBtn').textContent = 'เขียนทับคลาวด์ด้วยข้อมูลเครื่องนี้'; $('cfErr').textContent = '';
  $('cfKey2Row').hidden = true;
  $('conflictPanel').hidden = false;
  setStatus('conflict');
}
function closeKeyConflict(){ keyConflict = null; $('conflictPanel').hidden = true; $('cfKey').value = $('cfKey2').value = ''; $('cfErr').textContent = ''; }
$('cfMergeForm').addEventListener('submit', async e => {
  e.preventDefault();
  const btn = $('cfMergeBtn'), remote = keyConflict, s = session;
  if (!remote) return;
  btn.disabled = true; btn.textContent = 'กำลังถอดรหัส…'; $('cfErr').textContent = '';
  try {
    let r;
    try { r = await openVault($('cfKey').value, remote); }
    catch { return $('cfErr').textContent = 'Key นี้เปิดข้อมูลบนคลาวด์ไม่ได้'; }
    // our passwords are sealed under this device's Master Key: usually the same, otherwise ask for it
    const mine = await checkKey($('cfKey2').value || $('cfKey').value);
    if (!mine){
      $('cfKey2Row').hidden = false; $('cfKey2').focus();
      return $('cfErr').textContent = 'Key ของคลาวด์ต่างจากของเครื่องนี้ ใส่ Master Key ที่ใช้กับเครื่องนี้ด้วย';
    }
    if (session !== s || keyConflict !== remote) return;
    data = merge(await rekey(data, mine.pw, r.keys.pw), r.data);
    session = {meta: r.keys.meta, salt: r.salt}; base = remote.iv;
    closeKeyConflict(); render();
    await rememberDevice();
    await persist();
    toast('รวมข้อมูลแล้ว ต่อจากนี้ใช้ Key ของคลาวด์');
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
          <button class="chip" data-act="copy" data-f="pass" title="${shown ? 'คลิกเพื่อคัดลอกรหัสผ่าน' : 'ใส่ Master Key เพื่อดูและคัดลอกรหัสผ่าน'}">
            <span class="k">Pass</span><span class="v">${none ? '<span class="muted">—</span>' : shown ? esc(shown.text) : '••••••••••'}</span><span class="c">${none ? '' : shown ? 'คัดลอก' : 'ดูรหัส'}</span>
          </button>
          ${none ? '' : `<button class="ghost" data-act="peek" aria-label="${shown ? 'ซ่อนรหัสผ่าน' : 'แสดงรหัสผ่าน'}">${shown ? 'ซ่อน' : 'ดู'}</button>`}
        </div>
      </div>
      ${i.note ? `<div class="item-note">${esc(i.note)}</div>` : ''}
      <form class="confirm auth" data-auth hidden>
        <span data-authlabel style="flex-basis:100%"></span>
        <input type="password" autocomplete="off" placeholder="Master Key" aria-label="Master Key">
        <button class="primary" type="submit">ยืนยัน</button>
        <button type="button" data-act="authno">ยกเลิก</button>
        <span class="err" data-autherr></span>
      </form>
    </article>`; }).join('');
}
$('search').addEventListener('input', render);

const AUTH_LABEL = {reveal: () => 'ใส่ Master Key เพื่อดูรหัสผ่าน', edit: () => 'ใส่ Master Key เพื่อแก้ไข',
  del: item => `ใส่ Master Key เพื่อลบ “${item.site}” ถาวร`};
function askKey(card, item, then){
  const f = card.querySelector('[data-auth]');
  f.dataset.then = then; f.hidden = false;
  f.querySelector('[data-authlabel]').textContent = AUTH_LABEL[then](item);
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
  if (act === 'peek'){
    if (revealed.has(item.id)){ conceal(item.id); render(); }
    else askKey(card, item, 'reveal');
  }
  if (act === 'edit') askKey(card, item, 'edit');
  if (act === 'del') askKey(card, item, 'del');
  if (act === 'authno') card.querySelector('[data-auth]').hidden = true;
});

$('list').addEventListener('submit', async e => {
  const f = e.target.closest('[data-auth]'); if (!f) return;
  e.preventDefault();
  const id = f.closest('.item').dataset.id, input = f.querySelector('input'), btn = f.querySelector('[type=submit]');
  const label = btn.textContent;
  btn.disabled = true; btn.textContent = 'กำลังตรวจ…';
  const keys = await checkKey(input.value);
  input.value = ''; btn.disabled = false; btn.textContent = label;
  if (!keys){
    if (authFailed()) return;
    f.querySelector('[data-autherr]').textContent = 'Key ไม่ถูกต้อง';
    return input.focus();
  }
  authFails = 0;
  const item = data.items.find(i => i.id === id); if (!item) return render();
  let text = '';
  if (item.pw && f.dataset.then !== 'del'){
    try { text = await openPw(keys.pw, item.pw); }
    catch { f.querySelector('[data-autherr]').textContent = 'ถอดรหัสรายการนี้ไม่ได้'; return; }
  }
  if (f.dataset.then === 'reveal'){ reveal(id, text); render(); }
  if (f.dataset.then === 'edit'){ f.hidden = true; openEditor(item, text, keys.pw); }
  if (f.dataset.then === 'del'){
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
// editing arrives already authenticated (pwKey); adding asks for the Master Key inside the form, only if a password is set
let editOrigPass = '';
function openEditor(item, pass = '', pwKey = null){
  editingId = item ? item.id : null; editPw = pwKey; editOrigPass = pass;
  $('editTitle').textContent = item ? 'แก้ไขรายการ' : 'เพิ่มรายการ';
  $('fSite').value = item?.site || ''; $('fUser').value = item?.user || '';
  $('fPass').value = pass; $('fNote').value = item?.note || ''; $('fKey').value = '';
  $('fKeyRow').hidden = !!pwKey;
  $('editErr').textContent = '';
  $('editForm').hidden = false; $('fSite').focus();
}
function closeEditor(){ $('editForm').hidden = true; $('fPass').value = $('fKey').value = ''; editPw = null; editingId = null; editOrigPass = ''; }
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
  let pw = cur?.pw ?? null;
  if (pass !== editOrigPass || !cur){
    if (!pass) pw = null;
    else {
      let key = editPw;
      if (!key){
        const btn = e.submitter; if (btn) btn.disabled = true;
        const keys = await checkKey($('fKey').value);
        if (btn) btn.disabled = false;
        if (!keys){ if (!authFailed()) err.textContent = 'Master Key ไม่ถูกต้อง ใช้เข้ารหัสรหัสผ่านนี้ไม่ได้'; return; }
        authFails = 0; key = keys.pw;
      }
      pw = await sealPw(key, pass);
    }
  }
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
let importArmed = false;
$('importBtn').addEventListener('click', async () => {
  const err = $('importErr');
  let v; try { v = JSON.parse($('importBox').value); } catch {}
  if (!isBlob(v)) return err.textContent = 'ข้อความนี้ไม่ใช่ข้อความสำรองของตู้นี้';
  if (v.iter !== ITER) return err.textContent = 'ข้อความสำรองนี้ใช้การตั้งค่าเข้ารหัสที่ไม่รองรับ';
  if (!importArmed){ importArmed = true; $('importBtn').textContent = 'ยืนยัน: แทนที่ข้อมูลปัจจุบัน'; err.textContent = 'ข้อมูลในตู้และบนคลาวด์จะถูกแทนที่'; return; }
  // pushed (overwriting the cloud) once it is opened with its Master Key
  cache.set({blob: v, base, dirty: true, replace: true});
  importArmed = false; $('importBox').value = '';
  $('importBtn').textContent = 'กู้คืนจากข้อความนี้'; err.textContent = '';
  await forget(); toast('กู้คืนแล้ว ใส่ Key ของข้อมูลสำรองเพื่อเปิด');
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
  fb.getRedirectResult(auth).catch(e => { $('signinErr').textContent = authError(e); });
  fb.onAuthStateChanged(auth, u => {
    clearSession();
    user = u; lastRemote = undefined; dirty = false; replace = false; base = null;
    $('acctEmail').textContent = u ? (u.email || u.displayName || 'บัญชี Google') : '';
    if (!u) return show('signin');
    prepare();
  });
}
boot();
