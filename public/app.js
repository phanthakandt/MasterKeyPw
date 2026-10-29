// UI + Firebase sync. Google sign-in says who owns a vault (so accounts can be monitored and banned).
// Site, user and note sync as is; every password is sealed in the browser under its own item Key (vault-core.js),
// typed on every use. The Key and the plaintext password never leave this page; the derived key is dropped right after.
import { newVer, sealItem, resealItem, openItem, parseData, merge, sameData, FORMAT } from './vault-core.js';
import { firebaseConfig } from './firebase-config.js';

const FB = 'https://www.gstatic.com/firebasejs/10.14.1/';
const RETRY_MS = 20000, REVEAL_MS = 5000, MIN_ITEM_KEY = 6;
const $ = id => document.getElementById(id);
const empty = () => ({items:[], tomb:{}});

// ---------- state ----------
let user = null, open = false;    // open: the vault of `user` is on screen
let data = empty();
let base = null;      // ver of the remote copy `data` is based on (null = no remote doc)
let dirty = false;    // local changes not yet in Firestore
let replace = false;  // next push overwrites remote without the version check (restore from backup)
let rev = 0;          // bumps on every local change, so a push that raced with an edit doesn't clear `dirty`
let pendingRemote = null;
let editingId = null, editKey = null, unwatch = null;  // editKey: the item's key, held only while its editor is open
let revealed = new Map();                              // item id → {text, timer}
let auth, db, fb;

// ---------- local cache (offline copy, per Google account) ----------
const mem = {};
const cacheKey = () => 'vault.v4:' + user.uid;
const cache = {
  get(){ try { const v = JSON.parse(localStorage.getItem(cacheKey())); if (v) return v; } catch {} return mem[cacheKey()] ?? null; },
  set(rec){ mem[cacheKey()] = rec; try { localStorage.setItem(cacheKey(), JSON.stringify(rec)); return true; } catch { return false; } },
  del(){ delete mem[cacheKey()]; try { localStorage.removeItem(cacheKey()); } catch {} }
};
function saveLocal(){
  if (!cache.set({data, base, dirty, replace})) toast('เบราว์เซอร์นี้ไม่ให้บันทึกถาวร กรุณาสำรองข้อมูลไว้');
}
// copies left by the Master Key versions (the cloud was reset when they were retired)
function dropOldCopies(){
  try { for (const k of Object.keys(localStorage)) if (k === 'vault.v1' || k.startsWith('vault.v1:')) localStorage.removeItem(k); } catch {}
  try { indexedDB.deleteDatabase('vault'); } catch {}
}

// ---------- Firestore: users/{uid} = {v, data (JSON), ver, updatedAt} ----------
class Conflict extends Error { constructor(remote){ super('conflict'); this.remote = remote; } }
const ref = () => fb.doc(db, 'users', user.uid);
const pick = d => ({ver: d.ver, data: parseData(d.data) ?? empty()});

async function fetchRemote(){
  const s = await fb.getDocFromServer(ref());
  return s.exists() ? pick(s.data()) : null;
}
// expect: ver of the copy we built on (null = expect no doc); undefined = force overwrite
async function pushRemote(d, ver, expect){
  await fb.runTransaction(db, async tx => {
    const s = await tx.get(ref());
    const cur = s.exists() ? pick(s.data()) : null;
    if (expect !== undefined && (cur?.ver ?? null) !== expect) throw new Conflict(cur);
    tx.set(ref(), {v: FORMAT, data: JSON.stringify(d), ver, updatedAt: fb.serverTimestamp()});
  });
}

function startWatch(){
  stopWatch();
  unwatch = fb.onSnapshot(ref(), snap => {
    if (snap.metadata.hasPendingWrites || snap.metadata.fromCache) return;
    const remote = snap.exists() ? pick(snap.data()) : null;
    if ((remote?.ver ?? null) === base) return;
    pendingRemote = {remote}; sync();
  }, e => setStatus('error', e));
}
function stopWatch(){ if (unwatch){ unwatch(); unwatch = null; } }

// ---------- sync (single-flight: every remote read/merge/write goes through here) ----------
let syncing = null, again = false, retryTimer = null;
function sync(){
  if (syncing){ again = true; return syncing; }
  syncing = (async () => { do { again = false; await syncOnce(); } while (again && open); })()
    .finally(() => { syncing = null; });
  return syncing;
}

async function syncOnce(){
  const u = user; if (!open || !u) return;
  if (pendingRemote && !replace){
    const r = pendingRemote.remote; pendingRemote = null;
    absorb(r);
  }
  pendingRemote = null;
  if (!dirty) return setStatus('synced');
  if (!navigator.onLine) return setStatus('offline');
  setStatus('syncing');
  const myRev = rev, ver = newVer(), snapshot = data;
  try {
    await pushRemote(snapshot, ver, replace ? undefined : base);
    if (user !== u || !open) return;
    base = ver; replace = false;
    if (rev === myRev) dirty = false; else again = true;
    saveLocal();
    setStatus(dirty ? 'syncing' : 'synced');
  } catch (e){
    if (user !== u || !open) return;
    if (e instanceof Conflict){ absorb(e.remote); again = true; return; }
    setStatus(navigator.onLine ? 'error' : 'offline', e);
    clearTimeout(retryTimer); retryTimer = setTimeout(sync, RETRY_MS);
  }
}

// bring a newer remote copy into memory, merged with ours
function absorb(remote){
  if (!remote){ if (base !== null){ base = null; dirty = true; } return; }   // doc vanished → recreate it from this device
  if (remote.ver === base) return;
  const merged = merge(data, remote.data);
  const localChanged = !sameData(merged, data), needPush = !sameData(merged, remote.data);
  data = merged; base = remote.ver;
  if (needPush){ dirty = true; rev++; } else dirty = false;
  saveLocal();
  if (localChanged){ render(); toast('อัปเดตรายการจากอุปกรณ์อื่นแล้ว'); }
}

function persist(){
  dirty = true; rev++;
  saveLocal();
  sync();
}

const STATUS = {synced:'ซิงก์แล้ว', syncing:'กำลังซิงก์…', offline:'ออฟไลน์', error:'ซิงก์ไม่สำเร็จ'};
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
  for (const v of ['signin','msg','banned','vault']) $(v + 'View').hidden = view !== v;
  $('topActions').hidden = $('foot').hidden = view !== 'vault';
  $('acct').hidden = !user || view === 'signin';
}
function message(title, body, retry){
  $('msgTitle').textContent = title; $('msgBody').textContent = body;
  $('msgActions').hidden = !retry; $('msgRetry').onclick = retry || null;
  show('msg');
}
function closeVault(){
  stopWatch(); clearTimeout(retryTimer);
  for (const r of revealed.values()) clearTimeout(r.timer);
  revealed.clear();
  open = false; data = empty(); editingId = null; editKey = null; pendingRemote = null;
  $('list').innerHTML = ''; $('editForm').hidden = true;
}
function resetAccount(u){
  closeVault();
  user = u; base = null; dirty = false; replace = false; rev = 0;
  $('acctId').textContent = u ? (u.email || u.displayName || 'บัญชี Google') : '';
}

// after sign-in: start from the freshest copy (remote, unless this device has unsynced changes)
async function openAccount(){
  const u = user;
  message('กำลังเปิดตู้…', 'รอสักครู่');
  let rec = cache.get(), remote;
  try { remote = await fetchRemote(); } catch (e) { console.warn(e); remote = undefined; }
  if (user !== u) return;
  if (remote && (!rec || (!rec.dirty && rec.base !== remote.ver))) rec = {data: remote.data, base: remote.ver, dirty: false};
  if (!rec && remote === null) rec = {data: empty(), base: null, dirty: false};   // new account: the doc is created with the first item
  if (!rec) return message('เชื่อมต่อคลาวด์ไม่ได้', 'เครื่องนี้ยังไม่มีสำเนาตู้ และตรวจไม่ได้ว่ามีตู้บนคลาวด์หรือไม่ ตรวจการเชื่อมต่ออินเทอร์เน็ตแล้วลองอีกครั้ง', openAccount);
  data = parseData(rec.data) ?? empty(); base = rec.base ?? null; dirty = !!rec.dirty; replace = !!rec.replace; rev = 0;
  saveLocal();
  open = true;
  show('vault'); render(); startWatch(); sync();
}

// Signing out of a vault with no items: remove its doc and the local copy (the Google account stays, so it can still be monitored).
// Checked against the cloud first, and skipped when offline.
async function dropIfEmpty(){
  try {
    if (syncing) await syncing;
    if (!open || data.items.length || dirty || !navigator.onLine) return;
    const remote = await fetchRemote();
    if (remote?.data.items.length) return;
    closeVault();                         // stops the watcher and any further pushes
    if (remote) await fb.deleteDoc(ref());
    cache.del();
    if (remote) toast('ตู้ว่าง ลบออกแล้ว');
  } catch (e) { console.warn(e); }
}
async function signOutAll(){
  if (open && !data.items.length) await dropIfEmpty();
  closeVault();
  try { await fb.signOut(auth); } catch { toast('ออกจากระบบไม่สำเร็จ'); }
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
function showBanned(){ closeVault(); show('banned'); }

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
        <span class="keyfield"><input type="password" autocomplete="off" placeholder="Key ของรายการนี้" aria-label="Key" spellcheck="false" autocapitalize="off" autocorrect="off"><button type="button" class="ghost" data-peekfor>แสดง</button></span>
        <button class="primary" type="submit">ยืนยัน</button>
        <button type="button" data-act="authno">ยกเลิก</button>
        <span class="err" data-autherr></span>
      </form>
    </article>`; }).join('');
}
$('search').addEventListener('input', render);

// reveal / edit ask for the item's Key; delete only asks to confirm (no Key needed, so a forgotten Key can't trap an item)
const AUTH_LABEL = {
  reveal: () => 'ใส่ Key ของรายการนี้เพื่อดูรหัสผ่าน',
  edit: () => 'ใส่ Key ของรายการนี้เพื่อแก้ไข',
  del: item => `ลบ “${item.site}” ถาวร?`,
};
function askKey(card, item, then){
  const f = card.querySelector('[data-auth]'), needKey = then !== 'del';
  f.dataset.then = then; f.hidden = false;
  f.querySelector('[data-authlabel]').textContent = AUTH_LABEL[then](item);
  f.querySelector('.keyfield').hidden = !needKey;
  f.querySelector('[type=submit]').className = needKey ? 'primary' : 'danger';
  f.querySelector('[type=submit]').textContent = needKey ? 'ยืนยัน' : 'ลบเลย';
  f.querySelector('[data-autherr]').textContent = '';
  (needKey ? f.querySelector('input') : f.querySelector('[type=submit]')).focus();
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
  if (act === 'edit') item.pw ? askKey(card, item, 'edit') : openEditor(item);
  if (act === 'del') askKey(card, item, 'del');
  if (act === 'authno') card.querySelector('[data-auth]').hidden = true;
});

$('list').addEventListener('submit', async e => {
  const f = e.target.closest('[data-auth]'); if (!f) return;
  e.preventDefault();
  const id = f.closest('.item').dataset.id, input = f.querySelector('input'), btn = f.querySelector('[type=submit]');
  const then = f.dataset.then, u = user;
  const item = data.items.find(i => i.id === id); if (!item) return render();
  if (then === 'del'){
    conceal(id);
    data.items = data.items.filter(i => i.id !== id);
    data.tomb[id] = Date.now();
    persist(); render(); toast('ลบแล้ว');
    return;
  }
  const label = btn.textContent, pass = input.value;
  btn.disabled = true; btn.textContent = 'กำลังตรวจ…';
  let opened = null;
  if (pass) try { opened = await openItem(pass, item.pw); } catch {}
  input.value = ''; btn.disabled = false; btn.textContent = label;
  if (user !== u || !open) return;
  if (!opened){ f.querySelector('[data-autherr]').textContent = 'Key ไม่ถูกต้อง'; return input.focus(); }
  if (then === 'reveal'){ reveal(id, opened.text); render(); }
  if (then === 'edit'){ f.hidden = true; openEditor(item, opened.text, opened.k); }
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
  persist(); render(); toast('บันทึกแล้ว รหัสผ่านถูกเข้ารหัสด้วย Key ของรายการ');
});

// ---------- backup (passwords stay sealed under their item Keys) ----------
$('exportBtn').addEventListener('click', async () => {
  await copy(JSON.stringify({v: FORMAT, ...data}));
  toast('คัดลอกข้อความสำรองแล้ว นำไปเก็บไว้ในที่ปลอดภัย');
});
let importArmed = false;
function resetImport(){ importArmed = false; $('importBtn').textContent = 'กู้คืนจากข้อความนี้'; }
$('importBox').addEventListener('input', resetImport);
$('importBtn').addEventListener('click', () => {
  const err = $('importErr'), btn = $('importBtn');
  const d = parseData($('importBox').value);
  if (!d) return err.textContent = 'ข้อความนี้ไม่ใช่ข้อความสำรองของตู้นี้';
  if (!importArmed){ importArmed = true; btn.textContent = 'ยืนยัน: แทนที่ข้อมูลปัจจุบัน'; err.textContent = 'รายการในตู้และบนคลาวด์จะถูกแทนที่ด้วยข้อมูลสำรอง'; return; }
  data = d; replace = true;
  for (const id of [...revealed.keys()]) conceal(id);
  $('importBox').value = ''; resetImport(); err.textContent = '';
  persist(); render(); toast('กู้คืนแล้ว');
});

window.addEventListener('online', () => sync());
window.addEventListener('offline', () => open && setStatus('offline'));
document.addEventListener('visibilitychange', () => { if (!document.hidden && dirty) sync(); });

let tt; function toast(msg){
  const t = $('toast'); t.textContent = msg; t.classList.add('show');
  clearTimeout(tt); tt = setTimeout(() => t.classList.remove('show'), 2400);
}

// ---------- boot ----------
async function boot(){
  if (!crypto.subtle) return message('เบราว์เซอร์ไม่รองรับ', 'เบราว์เซอร์นี้ไม่รองรับการเข้ารหัส กรุณาเปิดด้วยเบราว์เซอร์รุ่นใหม่ผ่าน https');
  message('กำลังโหลด…', 'รอสักครู่');
  dropOldCopies();
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
  fb.onAuthStateChanged(auth, async u => {
    if (u && open && user?.uid === u.uid) return;
    resetAccount(u);
    if (!u) return show('signin');
    // a session left by the Master Key versions: not a Google account
    if (!u.providerData.some(p => p.providerId === 'google.com')){ await fb.signOut(auth); return; }
    message('กำลังเปิดตู้…', 'รอสักครู่');
    if (await isBanned(u.uid)) return user === u && showBanned();
    if (user === u) await openAccount();
  });
}
boot();
