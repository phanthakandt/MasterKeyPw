// UI + Firebase sync. Only sealed blobs {v, iter, salt, iv, ct} ever leave this file; the Master Key and plaintext stay in memory.
import { ITER, b64, deriveKey, seal, unseal, openBlob, isBlob, merge, sameData } from './vault-core.js';
import { firebaseConfig } from './firebase-config.js';

const FB = 'https://www.gstatic.com/firebasejs/10.14.1/';
const LEGACY = 'vault.v1', IDLE_MS = 5 * 60 * 1000, RETRY_MS = 20000, REVEAL_MS = 5000, MAX_AUTH_FAILS = 5;
const $ = id => document.getElementById(id);

// ---------- state ----------
let user = null, session = null;               // session = {key, salt} while unlocked
let data = {items:[], tomb:{}};
let base = null;      // iv of the remote version `data` is based on (null = no remote doc)
let dirty = false;    // local changes not yet in Firestore
let replace = false;  // next push overwrites remote without the version check (restore from backup / user chose overwrite)
let rev = 0;          // bumps on every local change, so a push that raced with an edit doesn't clear `dirty`
let lastRemote;       // undefined = unknown, null = no doc, else blob
let pendingRemote = null, keyConflict = null;
let editingId = null, idleTimer = null, unwatch = null;
let revealed = new Map(), authFails = 0;   // item id → auto-hide timer, for passwords unlocked by re-entering the Master Key
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
    const blob = await seal(s.key, s.salt, data);
    await pushRemote(blob, replace ? undefined : base);
    if (session !== s) return;
    base = blob.iv; lastRemote = blob; replace = false;
    if (rev === myRev){ dirty = false; saveLocal(blob); }
    else { saveLocal(await seal(s.key, s.salt, data)); again = true; }
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
    if (remote.salt !== b64(s.salt) || remote.iter !== ITER) throw 0;
    theirs = await unseal(s.key, remote);
  } catch { if (session === s) showKeyConflict(remote); return; }
  if (session !== s) return;
  const merged = merge(data, theirs);
  const localChanged = !sameData(merged, data), needPush = !sameData(merged, theirs);
  data = merged; base = remote.iv;
  if (needPush){ dirty = true; rev++; saveLocal(await seal(s.key, s.salt, data)); }
  else { dirty = false; saveLocal(remote); }
  if (localChanged){ render(); toast('อัปเดตรายการจากอุปกรณ์อื่นแล้ว'); }
}

async function persist(){
  dirty = true; rev++;
  saveLocal(await seal(session.key, session.salt, data));
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
  stopWatch(); clearTimeout(idleTimer); clearTimeout(retryTimer);
  session = null; data = {items:[], tomb:{}}; editingId = null; keyConflict = null; pendingRemote = null;
  for (const t of revealed.values()) clearTimeout(t);
  revealed.clear(); authFails = 0;
  $('list').innerHTML = ''; $('editForm').hidden = true; $('unlockKey').value = ''; $('cfKey').value = '';
  $('conflictPanel').hidden = true;
}
function lock(){ clearSession(); showLocked(); }

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
  showLocked();
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
  clearSession();
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
  session = {key: await deriveKey(a, salt), salt};
  data = {items:[], tomb:{}}; base = lastRemote?.iv ?? null; replace = false; rev = 0;
  await persist();
  $('setKey').value = $('setKey2').value = '';
  $('setupBtn').disabled = false; $('setupBtn').textContent = 'สร้างตู้นิรภัย';
  enterVault();
});

// ---------- unlock ----------
$('unlockForm').addEventListener('submit', async e => {
  e.preventDefault();
  const btn = $('unlockBtn'), err = $('unlockErr'), rec = cache.get();
  if (!rec) return lock();
  btn.disabled = true; btn.textContent = 'กำลังถอดรหัส…'; err.textContent = '';
  const pass = $('unlockKey').value;
  try {
    const r = await openBlob(pass, rec.blob);
    session = {key: r.key, salt: r.salt}; data = r.data;
    base = rec.base ?? null; dirty = !!rec.dirty; replace = !!rec.replace; rev = 0;
    // cloud re-keyed elsewhere but with the same Master Key → adopt its salt and merge now, while we still have the pass
    if (!replace && lastRemote && lastRemote.salt !== rec.blob.salt){
      try {
        const r2 = await openBlob(pass, lastRemote);
        session = {key: r2.key, salt: r2.salt}; data = merge(data, r2.data);
        base = lastRemote.iv; dirty = true; rev++;
      } catch {}
    }
    $('unlockKey').value = '';
    enterVault();
  } catch {
    err.textContent = 'Key ไม่ถูกต้อง ถอดรหัสไม่ได้';
    $('unlockKey').select();
  }
  btn.disabled = false; btn.textContent = 'ปลดล็อก';
});

function enterVault(){ show('vault'); render(); resetIdle(); startWatch(); sync(); }
$('lockBtn').addEventListener('click', () => { lock(); toast('ล็อกแล้ว'); });

// ---------- key conflict ----------
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
  const btn = $('cfMergeBtn'), remote = keyConflict, s = session;
  if (!remote) return;
  btn.disabled = true; btn.textContent = 'กำลังถอดรหัส…'; $('cfErr').textContent = '';
  try {
    const r = await openBlob($('cfKey').value, remote);
    if (session !== s || keyConflict !== remote) return;
    session = {key: r.key, salt: r.salt};
    data = merge(data, r.data); base = remote.iv;
    closeKeyConflict(); render();
    await persist();
    toast('รวมข้อมูลแล้ว ต่อจากนี้ใช้ Key ของคลาวด์ในการปลดล็อก');
  } catch {
    $('cfErr').textContent = 'Key นี้เปิดข้อมูลบนคลาวด์ไม่ได้';
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
  $('list').innerHTML = list.map(i => { const shown = revealed.has(i.id); return `
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
            <span class="k">Pass</span><span class="v">${shown ? (esc(i.pass) || '<span class="muted">—</span>') : '••••••••••'}</span><span class="c">${shown ? 'คัดลอก' : 'ดูรหัส'}</span>
          </button>
          <button class="ghost" data-act="peek" aria-label="${shown ? 'ซ่อนรหัสผ่าน' : 'แสดงรหัสผ่าน'}">${shown ? 'ซ่อน' : 'ดู'}</button>
        </div>
      </div>
      ${i.note ? `<div class="item-note">${esc(i.note)}</div>` : ''}
      <form class="confirm auth" data-auth hidden>
        <input type="password" autocomplete="off" placeholder="ใส่ Master Key เพื่อยืนยัน" aria-label="Master Key">
        <button class="primary" type="submit">ยืนยัน</button>
        <button type="button" data-act="authno">ยกเลิก</button>
        <span class="err" data-autherr></span>
      </form>
      <div class="confirm" data-confirm hidden>
        <span>ลบ “${esc(i.site)}” ถาวร?</span>
        <button class="danger" data-act="delyes">ลบเลย</button>
        <button data-act="delno">ไม่ลบ</button>
      </div>
    </article>`; }).join('');
}
$('search').addEventListener('input', render);

$('list').addEventListener('click', async e => {
  const btn = e.target.closest('[data-act]'); if (!btn) return;
  const card = btn.closest('.item'), item = data.items.find(i => i.id === card.dataset.id);
  if (!item) return render();
  const act = btn.dataset.act;
  if (act === 'copy'){
    if (btn.dataset.f === 'pass' && !revealed.has(item.id)) return askKey(card, 'reveal');
    const val = btn.dataset.f === 'user' ? item.user : item.pass;
    if (!val) return toast('ช่องนี้ว่างอยู่');
    await copy(val);
    btn.classList.add('copied'); btn.querySelector('.c').textContent = 'คัดลอกแล้ว';
    setTimeout(() => { btn.classList.remove('copied'); btn.querySelector('.c').textContent = 'คัดลอก'; }, 1500);
    toast(btn.dataset.f === 'user' ? 'คัดลอก username แล้ว' : 'คัดลอกรหัสผ่านแล้ว');
  }
  if (act === 'peek'){
    if (revealed.has(item.id)){ conceal(item.id); render(); }
    else askKey(card, 'reveal');
  }
  // the editor shows the password in clear, so it sits behind the same check
  if (act === 'edit') revealed.has(item.id) ? openEditor(item) : askKey(card, 'edit');
  if (act === 'authno') card.querySelector('[data-auth]').hidden = true;
  if (act === 'del') card.querySelector('[data-confirm]').hidden = false;
  if (act === 'delno') card.querySelector('[data-confirm]').hidden = true;
  if (act === 'delyes'){
    data.items = data.items.filter(i => i.id !== item.id);
    data.tomb[item.id] = Date.now();
    await persist(); render(); toast('ลบแล้ว');
  }
});

// ---------- re-enter Master Key to reveal / edit a password ----------
function askKey(card, then){
  const f = card.querySelector('[data-auth]');
  f.dataset.then = then; f.hidden = false;
  f.querySelector('[data-autherr]').textContent = '';
  f.querySelector('input').focus();
}
// derive from the typed pass + this vault's salt and check it opens something sealed with the session key
async function verifyKey(pass){
  const s = session;
  if (!pass || !s) return false;
  try {
    const key = await deriveKey(pass, s.salt);
    await unseal(key, await seal(s.key, s.salt, {items:[], tomb:{}}));
    return true;
  } catch { return false; }
}
function reveal(id){
  clearTimeout(revealed.get(id));
  revealed.set(id, setTimeout(() => { revealed.delete(id); render(); }, REVEAL_MS));
}
function conceal(id){ clearTimeout(revealed.get(id)); revealed.delete(id); }

$('list').addEventListener('submit', async e => {
  const f = e.target.closest('[data-auth]'); if (!f) return;
  e.preventDefault();
  const id = f.closest('.item').dataset.id, input = f.querySelector('input'), btn = f.querySelector('[type=submit]');
  const s = session;
  btn.disabled = true; btn.textContent = 'กำลังตรวจ…';
  const ok = await verifyKey(input.value);
  input.value = '';
  if (session !== s) return;
  btn.disabled = false; btn.textContent = 'ยืนยัน';
  if (!ok){
    if (++authFails >= MAX_AUTH_FAILS){ lock(); return toast('ใส่ Key ผิดหลายครั้ง ล็อกตู้แล้ว'); }
    f.querySelector('[data-autherr]').textContent = 'Key ไม่ถูกต้อง';
    return input.focus();
  }
  authFails = 0;
  reveal(id); render();
  const item = data.items.find(i => i.id === id);
  if (f.dataset.then === 'edit' && item) openEditor(item);
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
function openEditor(item){
  editingId = item ? item.id : null;
  $('editTitle').textContent = item ? 'แก้ไขรายการ' : 'เพิ่มรายการ';
  $('fSite').value = item?.site || ''; $('fUser').value = item?.user || '';
  $('fPass').value = item?.pass || ''; $('fNote').value = item?.note || '';
  $('editErr').textContent = '';
  $('editForm').hidden = false; $('fSite').focus();
}
$('addBtn').addEventListener('click', () => openEditor(null));
$('cancelBtn').addEventListener('click', () => { $('editForm').hidden = true; });
$('genBtn').addEventListener('click', () => {
  // rejection sampling: no modulo bias
  const cs = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_+=?';
  const lim = 256 - 256 % cs.length, out = [];
  while (out.length < 20) for (const x of crypto.getRandomValues(new Uint8Array(32))) if (x < lim && out.length < 20) out.push(cs[x % cs.length]);
  $('fPass').value = out.join('');
});
$('editForm').addEventListener('submit', async e => {
  e.preventDefault();
  const site = $('fSite').value.trim();
  if (!site) return $('editErr').textContent = 'ใส่ชื่อเว็บหรือแอปก่อนบันทึก';
  const fields = {site, user:$('fUser').value.trim(), pass:$('fPass').value, note:$('fNote').value.trim(), mt:Date.now()};
  const cur = editingId && data.items.find(i => i.id === editingId);
  if (cur) Object.assign(cur, fields);
  // also covers an item deleted on another device while this editor was open: its newer mt outlives the tombstone
  else data.items.push({id: editingId || (crypto.randomUUID ? crypto.randomUUID() : String(Date.now()+Math.random())), ...fields});
  await persist();
  $('editForm').hidden = true; render(); toast('บันทึกและเข้ารหัสแล้ว');
});

// ---------- backup ----------
$('exportBtn').addEventListener('click', async () => {
  await copy(JSON.stringify(await seal(session.key, session.salt, data)));
  toast('คัดลอกข้อความสำรองแล้ว นำไปเก็บไว้ในที่ปลอดภัย');
});
let importArmed = false;
$('importBtn').addEventListener('click', () => {
  const err = $('importErr');
  let v; try { v = JSON.parse($('importBox').value); } catch {}
  if (!isBlob(v)) return err.textContent = 'ข้อความนี้ไม่ใช่ข้อความสำรองของตู้นี้';
  if (v.iter !== ITER) return err.textContent = 'ข้อความสำรองนี้ใช้การตั้งค่าเข้ารหัสที่ไม่รองรับ';
  if (!importArmed){ importArmed = true; $('importBtn').textContent = 'ยืนยัน: แทนที่ข้อมูลปัจจุบัน'; err.textContent = 'ข้อมูลในตู้และบนคลาวด์จะถูกแทนที่'; return; }
  // pushed (overwriting the cloud) after the next successful unlock
  cache.set({blob: v, base, dirty: true, replace: true});
  importArmed = false; $('importBox').value = '';
  $('importBtn').textContent = 'กู้คืนจากข้อความนี้'; err.textContent = '';
  lock(); toast('กู้คืนแล้ว ใส่ Key ของข้อมูลสำรองเพื่อเปิด');
});

// ---------- auto-lock ----------
function resetIdle(){
  clearTimeout(idleTimer);
  if (session) idleTimer = setTimeout(() => { lock(); toast('ล็อกอัตโนมัติแล้ว'); }, IDLE_MS);
}
['click','keydown','pointermove','touchstart'].forEach(ev => document.addEventListener(ev, resetIdle, {passive:true}));
window.addEventListener('online', () => sync());
window.addEventListener('offline', () => session && setStatus('offline'));
document.addEventListener('visibilitychange', () => { if (!document.hidden && dirty) sync(); });

let tt; function toast(msg){
  const t = $('toast'); t.textContent = msg; t.classList.add('show');
  clearTimeout(tt); tt = setTimeout(() => t.classList.remove('show'), 2400);
}

// ---------- boot ----------
async function boot(){
  if (!crypto.subtle) return message('เบราว์เซอร์ไม่รองรับ', 'เบราว์เซอร์นี้ไม่รองรับการเข้ารหัส กรุณาเปิดด้วยเบราว์เซอร์รุ่นใหม่ผ่าน https');
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
