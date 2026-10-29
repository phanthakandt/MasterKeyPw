# ตู้นิรภัยรหัสผ่าน (ซิงก์ผ่าน Firebase)

ตัวจัดการรหัสผ่านแบบ zero-knowledge: เข้ารหัสในเบราว์เซอร์ด้วย PBKDF2-SHA256 600,000 รอบ → AES-256-GCM แล้วซิงก์เฉพาะ blob ที่เข้ารหัสแล้วข้ามอุปกรณ์ผ่าน Firestore **Master Key และข้อมูลที่ยังไม่เข้ารหัสไม่ออกจากเบราว์เซอร์**

## โครงสร้าง

```
public/
  index.html          หน้าตา + CSS (ภาษาไทย)
  app.js              UI, Firebase Auth, ซิงก์, จัดการการชนกัน
  vault-core.js       การเข้ารหัส + รูปแบบข้อมูล + merge (ไม่แตะเครือข่าย)
  firebase-config.js  ใส่ config ของโปรเจกต์ (หรือปล่อย null เมื่อ deploy บน Hosting)
firestore.rules       Security Rules
firebase.json         Hosting + Rules + security headers (CSP ฯลฯ)
vault.html            เวอร์ชันเดิมแบบไฟล์เดียว (ไม่ซิงก์) เก็บไว้อ้างอิง
```

## ขั้นตอนติดตั้ง

1. **สร้างโปรเจกต์** ที่ <https://console.firebase.google.com> → Add project
2. **เพิ่ม Web app**: Project settings → Your apps → `</>` (ยังไม่ต้องติ๊ก Hosting ตรงนี้ก็ได้)
3. **เปิด Authentication**: Build → Authentication → Get started → Sign-in method → **Google** → Enable → ใส่อีเมลติดต่อ → Save
   - เปิด **Email/Password** ค้างไว้ด้วย ถ้าเคยใช้รุ่นที่เข้าด้วย Master Key อย่างเดียว แอปต้องใช้เพื่อย้ายตู้เดิมเข้าบัญชี Google (Rules ไม่ให้บัญชีแบบนี้สร้างหรือเขียนตู้ใหม่ได้)
   - ถ้าใช้โดเมนของตัวเอง ให้เพิ่มใน Authentication → Settings → **Authorized domains** (`localhost`, `<project>.web.app` และ `<project>.firebaseapp.com` มีให้อยู่แล้ว)
4. **เปิด Firestore**: Build → Firestore Database → Create database → เลือก region → **Production mode**
5. **ใส่ config** (เลือกอย่างใดอย่างหนึ่ง)
   - ปล่อย `export const firebaseConfig = null;` ไว้ แล้ว deploy บน Firebase Hosting: แอปจะอ่าน config เองจาก `/__/firebase/init.json`
   - หรือคัดลอก `firebaseConfig` จาก Project settings → Your apps ไปวางใน `public/firebase-config.js` (ใช้เมื่อโฮสต์ที่อื่น)
   - ค่า `apiKey` ของ Firebase ไม่ใช่ความลับ ความปลอดภัยมาจาก Security Rules
6. **ติดตั้ง CLI และ deploy**
   ```bash
   npm install -g firebase-tools
   firebase login
   firebase use --add            # เลือกโปรเจกต์ที่สร้างไว้
   firebase deploy --only firestore:rules,hosting
   ```
7. เปิด `https://<project>.web.app` → เข้าสู่ระบบด้วย Google → ตั้ง Master Key (พิมพ์ 2 ครั้ง)

### ทางเลือก: โฮสต์บน GitHub Pages แทน Firebase Hosting
ยังใช้ Firebase Auth และ Firestore เหมือนเดิม เปลี่ยนแค่ที่วางหน้าเว็บ
1. ทำข้อ 1–4 ด้านบน แล้ว**ต้อง**วาง `firebaseConfig` ลงใน `public/firebase-config.js` (GitHub Pages ไม่มี `/__/firebase/init.json`)
2. ตั้ง Rules โดยไม่ต้องใช้ CLI: Firestore Database → แท็บ **Rules** → วางเนื้อหา `firestore.rules` ทั้งไฟล์ → **Publish**
3. Authentication → Settings → **Authorized domains** → Add domain → `<github-username>.github.io`
4. push ขึ้น GitHub แล้วไปที่ repo → Settings → Pages → Source: **GitHub Actions** จากนั้น workflow `.github/workflows/pages.yml` จะ deploy โฟลเดอร์ `public/` ทุกครั้งที่ push ขึ้น `main`
5. เปิด `https://<github-username>.github.io/<repo>/`

หมายเหตุ: บัญชี GitHub ฟรีเปิด Pages ได้เฉพาะ repo แบบ public ซึ่งการเปิดเผย `firebase-config.js` ไม่เป็นปัญหา (ดูข้อ 5 ด้านบน) แต่แนะนำให้จำกัด API key ให้ใช้ได้เฉพาะโดเมนของคุณ ที่ Google Cloud Console → APIs & Services → Credentials → Browser key → Website restrictions ส่วน CSP ใส่ไว้เป็น `<meta>` ใน `index.html` แล้ว (GitHub Pages ส่ง header เองไม่ได้)

ทดสอบในเครื่อง: `firebase emulators:start --only hosting` แล้วเปิด `http://localhost:5000` (ใช้ Auth/Firestore ตัวจริงของโปรเจกต์)

## การทำงาน

### เข้าสู่ระบบด้วย Google + Master Key
บัญชี Google บอกว่าใครเป็นเจ้าของตู้ (ใช้ซิงก์ ดูรายชื่อผู้ใช้ และแบนได้) ส่วน Master Key ใช้เปิดตู้ ไม่ถูกส่งออกจากเบราว์เซอร์ ใส่ครั้งเดียวต่ออุปกรณ์
- บัญชีที่ยังไม่มีตู้: ตั้ง Master Key โดยพิมพ์ 2 ครั้ง (อย่างน้อย 8 ตัว)
- ถ้าเคยใช้รุ่นที่เข้าด้วย Master Key อย่างเดียว ใส่ Key เดิมช่องเดียวพอ แอปจะเข้าบัญชีเดิมในหน่วยความจำ (ไม่แทนที่การเข้าสู่ระบบ Google) ดึงตู้เดิมมารวม แล้วลบเอกสาร บัญชีเดิม และสำเนาเก่าในเครื่องทิ้งหลังซิงก์ตู้ใหม่ขึ้นคลาวด์สำเร็จ สำเนาจากรุ่นเก่ากว่า (`vault.html` เดิม / บัญชี Google รุ่นแรก) ในเครื่องก็ถูกรวมแบบเดียวกัน
- กด "ออกจากระบบ" ขณะที่ตู้ไม่มีรายการเลย แอปจะลบเอกสารบน Firestore และสำเนาในเครื่องทิ้ง (บัญชี Google ยังอยู่) โดยเช็คกับคลาวด์ก่อนลบ และข้ามไปถ้าออฟไลน์
- การกู้คืนจากข้อความสำรองจะเข้ารหัสรายการใหม่ด้วย Master Key ของบัญชีปัจจุบันเสมอ

### ดูผู้ใช้และแบนบัญชี
- **ดูว่าใครใช้**: Firebase Console → Authentication → **Users** แสดงอีเมล วันที่สมัคร และวันที่เข้าใช้ล่าสุด ส่วนใครมีตู้แล้วดูที่ Firestore Database → collection `users` (ชื่อเอกสาร = User UID)
- **แบน (มีผลทันที)**: Firestore Database → Start collection / เปิด collection `banned` → Add document → Document ID = **User UID** ของคนนั้น (คัดลอกจากหน้า Users) → ใส่ field อะไรก็ได้ เช่น `reason` → Save Rules จะปฏิเสธการอ่านเขียนตู้ของบัญชีนั้น และแอปขึ้นว่า "บัญชีนี้ถูกระงับ"
- **ยกเลิกแบน**: ลบเอกสาร `banned/<UID>` นั้นทิ้ง
- **ปิดบัญชีทั้งบัญชี**: หน้า Users → เมนู ⋮ ท้ายแถว → **Disable account** (เข้าสู่ระบบใหม่ไม่ได้ แต่คนที่เปิดค้างอยู่ใช้ต่อได้ถึงราว 1 ชั่วโมง จึงควรใช้คู่กับ `banned`)
- ข้อมูลในตู้ยังเข้ารหัสด้วย Master Key ผู้ดูแลแบนได้ แต่เปิดดูรหัสผ่านของใครไม่ได้

### สิ่งที่เก็บบนคลาวด์
`users/{uid}` → `{v, iter, salt, iv, ct, updatedAt}` เท่านั้น ไม่มี plaintext, ไม่มี Key และไม่มี hash ของ Key ส่วน Rules บังคับว่า
- อ่านและเขียนได้เฉพาะเจ้าของ (`request.auth.uid == uid`) และห้ามลบ
- มีฟิลด์ได้แค่ 6 ตัวนี้, `iter >= 600000`, `updatedAt` ต้องเป็นเวลาเซิร์ฟเวอร์
- `iv` ต้องต่างจากของเดิมทุกครั้งที่อัปเดต (กัน IV ซ้ำ)

### ข้อมูลในเครื่อง
`localStorage["vault.v1:<uid>"]` = `{blob, base, dirty, replace}` ใช้เป็น cache ออฟไลน์ (แยกตามบัญชี) ทุกครั้งที่บันทึกจะเขียนลงเครื่องก่อน แล้วค่อยส่งขึ้น Firestore ถ้าออฟไลน์อยู่ ข้อมูลจะค้างสถานะ "รอซิงก์" และส่งให้เองเมื่อกลับมาออนไลน์ ถ้าเคยใช้ `vault.html` รุ่นเดิมในเบราว์เซอร์เดียวกัน ตู้เดิม (`vault.v1`) จะถูกย้ายเข้าบัญชีแรกที่เข้าสู่ระบบโดยอัตโนมัติ

### Key แยกของแต่ละรายการ
รหัสผ่านแต่ละรายการเข้ารหัสด้วย Key ของรายการนั้นเอง (`pw = {salt, iv, ct}` ใช้ PBKDF2 600,000 รอบกับ salt สุ่มของรายการ แล้ว HKDF) ตั้ง Key ตอนเพิ่มรายการ และเปลี่ยนได้ตอนแก้ไข Master Key เปิดรหัสผ่านของรายการที่มี Key ของตัวเองไม่ได้ แต่ใช้ลบรายการได้เมื่อลืม Key ของรายการ ส่วนรายการเก่าที่สร้างก่อนมี Key แยก (`pw` ไม่มี `salt`) ยังเปิดด้วย Master Key จนกว่าจะตั้ง Key ใหม่ตอนแก้ไข

### กันการเขียนทับข้ามเครื่อง
- ทุกเวอร์ชันมี `iv` สุ่มใหม่ ใช้ `iv` นี้เป็นตัวระบุเวอร์ชัน (`base`) ว่าข้อมูลในเครื่องสร้างต่อจากเวอร์ชันไหนบนคลาวด์
- ตอนเขียนใช้ **Firestore transaction**: ถ้า `iv` บนคลาวด์ไม่ตรงกับ `base` แสดงว่ามีอุปกรณ์อื่นเขียนก่อน จึงยกเลิกการเขียน แล้วดึงเวอร์ชันนั้นมาถอดรหัสและ merge ก่อนเขียนใหม่ (ใช้ `iv` แทน `updatedAt` เพราะรู้ค่าได้ทันทีโดยไม่ต้องอ่านซ้ำหลังเขียน จึงไม่มีช่องว่างให้แข่งกันเขียน)
- ขณะปลดล็อกอยู่ มี `onSnapshot` ฟังการเปลี่ยนแปลงแบบเรียลไทม์ อุปกรณ์อื่นแก้ไขเมื่อไหร่ รายการจะอัปเดตทันทีพร้อมแจ้งเตือน
- **Merge** ทำในเบราว์เซอร์หลังถอดรหัส: แต่ละรายการมีเวลาแก้ไขล่าสุด (`mt`) อันที่ใหม่กว่าชนะ การลบเก็บเป็น tombstone (เก็บไว้ 1 ปี) เพื่อไม่ให้รายการที่ลบแล้วกลับมา ทั้ง `mt` และ tombstone อยู่ใน ciphertext คลาวด์จึงไม่เห็น
- ถ้าคลาวด์ถูกเข้ารหัสด้วย **salt/Key อื่น** (เช่น อีกเครื่องกู้คืนข้อมูลสำรองที่ใช้ Key ต่างกัน) เครื่องนี้จะหยุดซิงก์และให้ผู้ใช้เลือกเองว่าจะ "รวมข้อมูล" (ใส่ Key ของคลาวด์) หรือ "เขียนทับคลาวด์"

### การเข้ารหัส 2 ชั้น (`v:3`)
`PBKDF2-SHA256(Master Key, salt, 600,000)` → 256 บิต → HKDF แยกเป็นกุญแจ 2 ดอก
- **กุญแจรายการ (meta)**: เข้ารหัส payload `{items:[{id,site,user,note,mt,pw}], tomb:{id:ms}}` ใส่ Master Key ครั้งเดียวต่ออุปกรณ์ แล้วเก็บกุญแจนี้ใน IndexedDB แบบ non-extractable (ดึงค่าดิบออกมาไม่ได้) ครั้งต่อไปจึงเปิดรายการได้ทันที
- **กุญแจรหัสผ่าน (pw)**: เข้ารหัสรหัสผ่านแต่ละตัวแยกกัน (`pw = {iv, ct}`) ไม่ถูกเก็บไว้ที่ไหนเลย ต้องพิมพ์ Master Key ทุกครั้งที่จะดู คัดลอก แก้ไข ลบ หรือเพิ่มรหัสผ่าน ถ้ามีคนแอบใช้เครื่องที่จำตู้ไว้ จะเห็นได้แค่ชื่อเว็บกับ username
- ทั้งสองดอกสร้างจาก Master Key เดียวกัน ทุกอุปกรณ์จึงได้กุญแจตรงกันโดยไม่ต้องส่งกุญแจข้ามเครื่อง
- ใส่ Master Key ผิด 5 ครั้งติด (ตู้ถูกล็อก ยังอยู่ในบัญชี Google) หรือกด "ออกจากระบบ" เครื่องจะลืมกุญแจรายการ ครั้งหน้าต้องใส่ Master Key ใหม่

`v:1`/`v:2` (รุ่นเก่า เข้ารหัสทั้งก้อนและเก็บรหัสผ่านไว้ข้างในโดยไม่แยกชั้น) จะถูกแปลงเป็น `v:3` ให้อัตโนมัติเมื่อปลดล็อกด้วย Master Key ข้อความสำรองแบบเก่ายังกู้คืนได้

### การกู้คืนจากข้อความสำรอง
จะแทนที่ทั้งข้อมูลในเครื่องและบนคลาวด์หลังจากปลดล็อกด้วย Key ของข้อมูลสำรองได้สำเร็จ อุปกรณ์อื่นที่ใช้ Key เดียวกันจะ merge รายการที่ใหม่กว่าของตัวเองกลับเข้ามา ส่วนอุปกรณ์ที่ใช้ Key ต่างกันจะเห็นหน้าต่างให้ตัดสินใจ

## หมายเหตุด้านความปลอดภัย
- CSP ใน `firebase.json` อนุญาตเฉพาะ gstatic/Google APIs/Google Fonts ถ้าเปลี่ยน `authDomain` เป็นโดเมนของตัวเอง ให้เพิ่มโดเมนนั้นใน `frame-src`
- Firebase SDK โหลดจาก `www.gstatic.com/firebasejs/10.14.1` ถ้าจะอัปเวอร์ชันให้แก้ค่า `FB` ใน `public/app.js`
- ไม่มี service worker ต้องออนไลน์ตอนเปิดหน้าเว็บ แต่ถ้าเน็ตหลุดระหว่างใช้งาน ยังแก้ไขต่อได้และจะซิงก์เมื่อเน็ตกลับมา
