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
let revealed = new Map();                              // entry key → {text, timer}
let shared = new Map(), sharedSubs = [];               // shared/{id} docs I own or can view: id → {id, owner, viewers, item}
let sharingKey = null, transferArmed = null;           // card whose share panel is open; viewer picked for ownership transfer
let auth, db, fb;
const myEmail = () => (user?.email || '').toLowerCase();

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

// ---------- shared items: shared/{id} = {owner, viewers: [email], data (JSON of one item), ver, updatedAt} ----------
// One copy for everyone: the owner edits it, viewers only read (same item Key). The owner can hand ownership to a viewer.
const sharedRef = id => fb.doc(db, 'shared', id);
const itemJson = i => JSON.stringify({site: i.site, user: i.user, note: i.note, pw: i.pw, mt: i.mt});
function pickShared(id, d){
  const item = parseData({items: [{id, ...(() => { try { return JSON.parse(d.data); } catch { return {}; } })()}]})?.items[0];
  return item && typeof d.owner === 'string' && Array.isArray(d.viewers) ? {id, owner: d.owner, viewers: d.viewers, item} : null;
}
function startShared(){
  stopShared();
  const me = myEmail(); if (!me) return;
  const col = fb.collection(db, 'shared');
  for (const [field, op] of [['owner', '=='], ['viewers', 'array-contains']]){
    const mine = new Set();
    sharedSubs.push(fb.onSnapshot(fb.query(col, fb.where(field, op, me)), snap => {
      const before = sharedSig();
      for (const id of mine) shared.delete(id);
      mine.clear();
      for (const d of snap.docs){ const s = pickShared(d.id, d.data()); if (s){ shared.set(d.id, s); mine.add(d.id); } }
      for (const k of [...revealed.keys()]) if (k.startsWith('s:') && !shared.has(k.slice(2))) conceal(k);
      // re-render only on a real change, so a Key being typed into an open card isn't wiped
      if (sharedSig() !== before) render();
    }, e => console.warn(e)));
  }
}
const sharedSig = () => JSON.stringify([...shared.values()].sort((a, b) => a.id < b.id ? -1 : 1));
function stopShared(){ sharedSubs.forEach(u => u()); sharedSubs = []; shared.clear(); }
// read-modify-write in a transaction; fn(current doc data or null) returns the new fields
async function writeShared(id, fn){
  await fb.runTransaction(db, async tx => {
    const s = await tx.get(sharedRef(id));
    const next = fn(s.exists() ? s.data() : null);
    tx.set(sharedRef(id), {...next, ver: newVer(), updatedAt: fb.serverTimestamp()});
  });
}
const shareFail = e => { console.warn(e); toast(e?.message === 'gone' ? 'รายการนี้ไม่ได้แชร์อยู่แล้ว' : 'แชร์ไม่สำเร็จ ลองอีกครั้ง'); };
async function shareTo(entry, email){
  if (entry.kind === 'mine'){
    const item = entry.item;
    await writeShared(item.id, cur => { if (cur) throw new Error('exists'); return {owner: myEmail(), viewers: [email], data: itemJson(item)}; });
    // the personal copy goes away (tombstone, so other devices drop it too): one copy for everyone
    conceal(item.id);
    data.items = data.items.filter(i => i.id !== item.id); data.tomb[item.id] = Date.now();
    persist();
    sharingKey = 's:' + item.id;
  } else {
    await writeShared(entry.doc.id, cur => {
      if (!cur || cur.owner !== myEmail()) throw new Error('gone');
      return {owner: cur.owner, viewers: [...new Set([...cur.viewers, email])], data: cur.data};
    });
  }
}
const unshare = (id, email) => writeShared(id, cur => {
  if (!cur || cur.owner !== myEmail()) throw new Error('gone');
  return {owner: cur.owner, viewers: cur.viewers.filter(v => v !== email), data: cur.data};
});
const transfer = (id, email) => writeShared(id, cur => {
  if (!cur || cur.owner !== myEmail() || !cur.viewers.includes(email)) throw new Error('gone');
  return {owner: email, viewers: [...cur.viewers.filter(v => v !== email), cur.owner], data: cur.data};
});
const leaveShared = id => writeShared(id, cur => {
  if (!cur || !cur.viewers.includes(myEmail())) throw new Error('gone');
  return {owner: cur.owner, viewers: cur.viewers.filter(v => v !== myEmail()), data: cur.data};
});

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
  stopWatch(); stopShared(); clearTimeout(retryTimer);
  for (const r of revealed.values()) clearTimeout(r.timer);
  revealed.clear();
  open = false; data = empty(); editingId = null; editKey = null; pendingRemote = null; sharingKey = null; transferArmed = null;
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
  show('vault'); render(); startWatch(); startShared(); sync();
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
// entries: my own items, shared items I own (editable, 's:' keys) and items shared with me (read-only)
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function entries(){
  const out = data.items.map(i => ({key: i.id, kind: 'mine', item: i}));
  for (const s of shared.values()) out.push({key: 's:' + s.id, kind: s.owner === myEmail() ? 'owned' : 'recv', item: s.item, doc: s});
  return out;
}
const entryOf = key => entries().find(e => e.key === key);
function sharePanel(e){
  const viewers = e.kind === 'owned' ? e.doc.viewers : [];
  return `
      <div class="share" data-share>
        ${viewers.length ? viewers.map(v => `
        <div class="share-row">
          <span class="who">${esc(v)}</span>
          ${transferArmed === e.key + '|' + v
            ? `<button class="danger" data-act="transfer" data-email="${esc(v)}">ยืนยัน: ให้ ${esc(v)} เป็นเจ้าของ</button><button class="ghost" data-act="transferno">ยกเลิก</button>`
            : `<button class="ghost" data-act="transfer" data-email="${esc(v)}">โอนเป็นเจ้าของ</button><button class="ghost" data-act="unshare" data-email="${esc(v)}">เอาออก</button>`}
        </div>`).join('') : '<span class="muted">ยังไม่ได้แชร์ให้ใคร</span>'}
        ${transferArmed?.startsWith(e.key + '|') ? '<span class="muted">โอนแล้วคุณจะกลายเป็นผู้ดู แก้ไข ลบ หรือแชร์ต่อไม่ได้ และเอาคืนเองไม่ได้</span>' : ''}
        <form data-shareform novalidate>
          <input type="email" placeholder="อีเมล Gmail ของผู้รับ" aria-label="อีเมลผู้รับ" autocomplete="off" spellcheck="false">
          <button class="primary" type="submit">แชร์</button>
          <button type="button" data-act="shareclose">ปิด</button>
        </form>
        <span class="muted">ผู้รับดูได้อย่างเดียว ต้องใช้ Key ของรายการนี้ดูรหัสผ่าน ให้บอก Key ทางอื่น (ไม่ใช่อีเมล)</span>
        <span class="err" data-shareerr></span>
      </div>`;
}
function render(){
  const all = entries();
  const q = $('search').value.trim().toLowerCase();
  const list = all.filter(({item: i}) => !q || i.site.toLowerCase().includes(q) || (i.user||'').toLowerCase().includes(q))
                  .sort((a,b) => a.item.site.localeCompare(b.item.site, 'th'));
  $('countLabel').textContent = all.length + ' รายการ';
  if (!all.length){
    $('list').innerHTML = '<div class="empty">ตู้ยังว่างอยู่<br>กด <strong>+ เพิ่มรายการ</strong> เพื่อฝาก username และรหัสผ่านแรก</div>';
    return;
  }
  if (!list.length){ $('list').innerHTML = '<div class="empty">ไม่พบรายการที่ตรงกับคำค้น</div>'; return; }
  $('list').innerHTML = list.map(e => {
    const i = e.item, shown = revealed.get(e.key), none = !i.pw;
    const actions = e.kind === 'recv'
      ? '<button class="ghost" data-act="leave">ออกจากการแชร์</button>'
      : `<button class="ghost" data-act="edit">แก้ไข</button><button class="ghost" data-act="share">แชร์</button><button class="ghost" data-act="del">ลบ</button>`;
    const badge = e.kind === 'recv' ? `<span class="badge recv">แชร์จาก ${esc(e.doc.owner)} · ดูได้อย่างเดียว</span>`
      : e.kind === 'owned' ? `<span class="badge">แชร์ให้ ${e.doc.viewers.length} คน</span>` : '';
    return `
    <article class="item" data-id="${esc(e.key)}">
      <div class="item-head">
        <span class="item-title">${esc(i.site)}</span>
        <span class="row" style="gap:2px;flex-wrap:nowrap">${actions}</span>
      </div>
      ${badge}
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
      ${sharingKey === e.key && e.kind !== 'recv' ? sharePanel(e) : ''}
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

// reveal / edit ask for the item's Key; delete and leaving a share only ask to confirm (a forgotten Key can't trap an item)
const AUTH_LABEL = {
  reveal: () => 'ใส่ Key ของรายการนี้เพื่อดูรหัสผ่าน',
  edit: () => 'ใส่ Key ของรายการนี้เพื่อแก้ไข',
  del: e => e.kind === 'owned' ? `ลบ “${e.item.site}” ถาวร? รายการจะหายจากทุกคนที่แชร์ด้วย` : `ลบ “${e.item.site}” ถาวร?`,
  leave: e => `เลิกดู “${e.item.site}” ที่ ${e.doc.owner} แชร์ให้? จะกลับมาเห็นได้เมื่อเจ้าของแชร์ให้ใหม่`,
};
function askKey(card, e, then){
  const f = card.querySelector('[data-auth]'), needKey = then === 'reveal' || then === 'edit';
  f.dataset.then = then; f.hidden = false;
  f.querySelector('[data-authlabel]').textContent = AUTH_LABEL[then](e);
  f.querySelector('.keyfield').hidden = !needKey;
  f.querySelector('[type=submit]').className = needKey ? 'primary' : 'danger';
  f.querySelector('[type=submit]').textContent = needKey ? 'ยืนยัน' : then === 'leave' ? 'ออกจากการแชร์' : 'ลบเลย';
  f.querySelector('[data-autherr]').textContent = '';
  (needKey ? f.querySelector('input') : f.querySelector('[type=submit]')).focus();
}
function reveal(key, text){
  conceal(key);
  revealed.set(key, {text, timer: setTimeout(() => { revealed.delete(key); render(); }, REVEAL_MS)});
}
function conceal(key){ clearTimeout(revealed.get(key)?.timer); revealed.delete(key); }

$('list').addEventListener('click', async ev => {
  const btn = ev.target.closest('[data-act]'); if (!btn) return;
  const card = btn.closest('.item'), e = entryOf(card.dataset.id);
  if (!e) return render();
  const act = btn.dataset.act, item = e.item;
  if (act === 'copy'){
    const isPass = btn.dataset.f === 'pass';
    if (isPass && item.pw && !revealed.has(e.key)) return askKey(card, e, 'reveal');
    const val = isPass ? revealed.get(e.key)?.text : item.user;
    if (!val) return toast('ช่องนี้ว่างอยู่');
    await copy(val);
    btn.classList.add('copied'); btn.querySelector('.c').textContent = 'คัดลอกแล้ว';
    setTimeout(() => { btn.classList.remove('copied'); btn.querySelector('.c').textContent = 'คัดลอก'; }, 1500);
    toast(isPass ? 'คัดลอกรหัสผ่านแล้ว' : 'คัดลอก username แล้ว');
  }
  if (act === 'edit') item.pw ? askKey(card, e, 'edit') : openEditor(e);
  if (act === 'del') askKey(card, e, 'del');
  if (act === 'leave') askKey(card, e, 'leave');
  if (act === 'authno') card.querySelector('[data-auth]').hidden = true;
  if (act === 'share'){ sharingKey = sharingKey === e.key ? null : e.key; transferArmed = null; render(); if (sharingKey) $('list').querySelector('[data-shareform] input')?.focus(); }
  if (act === 'transferno'){ transferArmed = null; render(); }
  if (act === 'shareclose'){ sharingKey = null; transferArmed = null; render(); }
  if (act === 'unshare' && e.kind === 'owned'){
    try { await unshare(e.doc.id, btn.dataset.email); toast('เอาออกจากการแชร์แล้ว ถ้าเขาเคยดูรหัสไปแล้ว ควรเปลี่ยนรหัสผ่านที่เว็บนั้น'); } catch (x) { shareFail(x); }
  }
  if (act === 'transfer' && e.kind === 'owned'){
    const email = btn.dataset.email, armKey = e.key + '|' + email;
    if (transferArmed !== armKey){ transferArmed = armKey; return render(); }
    transferArmed = null;
    try { await transfer(e.doc.id, email); sharingKey = null; toast('โอนความเป็นเจ้าของให้ ' + email + ' แล้ว'); } catch (x) { shareFail(x); }
  }
});

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
$('list').addEventListener('submit', async ev => {
  const sf = ev.target.closest('[data-shareform]');
  if (sf){
    ev.preventDefault();
    const card = sf.closest('.item'), e = entryOf(card.dataset.id), err = card.querySelector('[data-shareerr]');
    const input = sf.querySelector('input'), btn = sf.querySelector('[type=submit]'), email = input.value.trim().toLowerCase();
    if (!e || e.kind === 'recv') return render();
    if (!EMAIL.test(email)) return err.textContent = 'ใส่อีเมลให้ถูกต้อง';
    if (email === myEmail()) return err.textContent = 'แชร์ให้ตัวเองไม่ได้';
    if (e.kind === 'owned' && e.doc.viewers.includes(email)) return err.textContent = 'แชร์ให้อีเมลนี้อยู่แล้ว';
    btn.disabled = true; err.textContent = '';
    try { await shareTo(e, email); input.value = ''; toast('แชร์ให้ ' + email + ' แล้ว อย่าลืมบอก Key ของรายการให้เขาทางอื่น'); }
    catch (x) { shareFail(x); }
    finally { btn.disabled = false; }
    return;
  }
  const f = ev.target.closest('[data-auth]'); if (!f) return;
  ev.preventDefault();
  const key = f.closest('.item').dataset.id, input = f.querySelector('input'), btn = f.querySelector('[type=submit]');
  const then = f.dataset.then, u = user, e = entryOf(key);
  if (!e) return render();
  if (then === 'del' || then === 'leave'){
    conceal(key);
    if (e.kind === 'mine'){
      data.items = data.items.filter(i => i.id !== e.item.id);
      data.tomb[e.item.id] = Date.now();
      persist(); render(); toast('ลบแล้ว');
    } else {
      btn.disabled = true;
      try {
        if (then === 'del'){ await fb.deleteDoc(sharedRef(e.doc.id)); toast('ลบแล้ว'); }
        else { await leaveShared(e.doc.id); toast('ออกจากการแชร์แล้ว'); }
      } catch (x) { shareFail(x); }
      btn.disabled = false;
    }
    return;
  }
  const label = btn.textContent, pass = input.value;
  btn.disabled = true; btn.textContent = 'กำลังตรวจ…';
  let opened = null;
  if (pass) try { opened = await openItem(pass, e.item.pw); } catch {}
  input.value = ''; btn.disabled = false; btn.textContent = label;
  if (user !== u || !open) return;
  if (!opened){ f.querySelector('[data-autherr]').textContent = 'Key ไม่ถูกต้อง'; return input.focus(); }
  if (then === 'reveal'){ reveal(key, opened.text); render(); }
  if (then === 'edit'){ f.hidden = true; openEditor(e, opened.text, opened.k); }
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
// e = the entry being edited (mine or a shared item I own), null for a new item
function openEditor(e, pass = '', k = null){
  const item = e?.item;
  editingId = e ? e.key : null; editKey = k; editOrigPass = pass;
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
  const entry = editingId && entryOf(editingId), cur = entry?.item;
  if (editingId?.startsWith('s:') && !entry) return err.textContent = 'รายการนี้ถูกลบหรือโอนไปแล้ว';
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
  if (entry && entry.kind !== 'mine'){
    // a shared item: written straight to its shared doc, everyone sees the change
    try {
      await writeShared(entry.doc.id, d => {
        if (!d || d.owner !== myEmail()) throw new Error('gone');
        return {owner: d.owner, viewers: d.viewers, data: itemJson(fields)};
      });
    } catch (x) { return shareFail(x); }
    conceal(editingId); closeEditor(); render(); toast('บันทึกแล้ว ทุกคนที่แชร์ด้วยเห็นการเปลี่ยนแปลง');
    return;
  }
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
