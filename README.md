# ตู้นิรภัยรหัสผ่าน (ซิงก์ผ่าน Firebase)

ตัวจัดการรหัสผ่านที่ซิงก์ข้ามอุปกรณ์ผ่าน Firestore เข้าด้วยบัญชี Google รหัสผ่านแต่ละรายการเข้ารหัสในเบราว์เซอร์ด้วย Key ของรายการนั้น (PBKDF2-SHA256 600,000 รอบ → AES-256-GCM) **ตัว Key และรหัสผ่านจริงไม่ออกจากเบราว์เซอร์** ส่วนชื่อเว็บ username และโน้ต เก็บบนคลาวด์แบบอ่านได้ (คุ้มครองด้วยบัญชี Google และ Security Rules)

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
7. เปิด `https://<project>.web.app` → เข้าสู่ระบบด้วย Google → เพิ่มรายการได้เลย

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

### เข้าสู่ระบบด้วย Google (ไม่มี Master Key)
- กดเข้าสู่ระบบด้วย Google แล้วเห็นรายการทันที ทุกอุปกรณ์ที่เข้าด้วยบัญชีเดียวกันเห็นตู้เดียวกัน
- เพิ่มรายการที่มีรหัสผ่านต้องตั้ง Key ของรายการ (อย่างน้อย 6 ตัว พิมพ์ 2 ครั้ง) ดูหรือแก้ไขรหัสผ่านต้องใส่ Key นั้นทุกครั้ง รหัสที่แสดงซ่อนเองใน 5 วินาที
- ลบรายการแค่กดยืนยัน ไม่ต้องใช้ Key (ลืม Key ก็ยังลบได้)
- ตู้ของบัญชีใหม่ยังไม่ถูกสร้างบนคลาวด์จนกว่าจะเพิ่มรายการแรก กด "ออกจากระบบ" ขณะที่ตู้ไม่มีรายการ แอปจะลบเอกสารบน Firestore และสำเนาในเครื่องทิ้ง (บัญชี Google ยังอยู่) โดยเช็คกับคลาวด์ก่อน และข้ามไปถ้าออฟไลน์
- ใครเข้าบัญชี Google ของคุณได้ จะเห็นชื่อเว็บ username และโน้ต แต่ดูรหัสผ่านไม่ได้ถ้าไม่รู้ Key ของแต่ละรายการ

### ดูผู้ใช้และแบนบัญชี
- **ดูว่าใครใช้**: Firebase Console → Authentication → **Users** แสดงอีเมล วันที่สมัคร และวันที่เข้าใช้ล่าสุด ส่วนใครมีตู้แล้วดูที่ Firestore Database → collection `users` (ชื่อเอกสาร = User UID)
- **แบน (มีผลทันที)**: Firestore Database → Start collection / เปิด collection `banned` → Add document → Document ID = **User UID** ของคนนั้น (คัดลอกจากหน้า Users) → ใส่ field อะไรก็ได้ เช่น `reason` → Save Rules จะปฏิเสธการอ่านเขียนตู้ของบัญชีนั้น และแอปขึ้นว่า "บัญชีนี้ถูกระงับ"
- **ยกเลิกแบน**: ลบเอกสาร `banned/<UID>` นั้นทิ้ง
- **ปิดบัญชีทั้งบัญชี**: หน้า Users → เมนู ⋮ ท้ายแถว → **Disable account** (เข้าสู่ระบบใหม่ไม่ได้ แต่คนที่เปิดค้างอยู่ใช้ต่อได้ถึงราว 1 ชั่วโมง จึงควรใช้คู่กับ `banned`)
- ผู้ดูแลเห็นชื่อเว็บและ username ในเอกสาร `users` ได้ แต่เปิดรหัสผ่านของใครไม่ได้

### สิ่งที่เก็บบนคลาวด์
`users/{uid}` → `{v: 4, data, ver, updatedAt}`
- `data` = JSON ของ `{items:[{id, site, user, note, mt, pw}], tomb:{id: ms}}` โดย `pw = {salt, iv, ct}` คือรหัสผ่านที่เข้ารหัสแล้ว (หรือ `null` ถ้าไม่มีรหัสผ่าน) ไม่มี Key และไม่มี hash ของ Key
- Rules บังคับว่า อ่าน เขียน ลบ ได้เฉพาะเจ้าของที่เข้าด้วย Google และไม่ถูกแบน, มีฟิลด์ได้แค่ 4 ตัวนี้, `updatedAt` ต้องเป็นเวลาเซิร์ฟเวอร์, `ver` ต้องเปลี่ยนทุกครั้งที่อัปเดต
- `banned/{uid}` เจ้าของอ่านได้อย่างเดียว เขียนได้จาก Firebase Console เท่านั้น

### ข้อมูลในเครื่อง
`localStorage["vault.v4:<uid>"]` = `{data, base, dirty, replace}` ใช้เป็น cache ออฟไลน์ (แยกตามบัญชี) ทุกครั้งที่บันทึกจะเขียนลงเครื่องก่อน แล้วค่อยส่งขึ้น Firestore ถ้าออฟไลน์อยู่ ข้อมูลจะค้างสถานะ "รอซิงก์" และส่งให้เองเมื่อกลับมาออนไลน์ สำเนาจากรุ่นที่ใช้ Master Key (`vault.v1*` และ IndexedDB `vault`) ถูกลบทิ้งเมื่อเปิดเว็บ

### Key แยกของแต่ละรายการ
`pw = {salt, iv, ct}`: AES-256-GCM ด้วยกุญแจจาก `HKDF(PBKDF2-SHA256(Key ของรายการ, salt สุ่มของรายการ, 600,000))` IV สุ่มใหม่ทุกครั้งที่เข้ารหัส Key พิมพ์ทุกครั้งที่ใช้ ไม่ถูกเก็บหรือส่งไปที่ไหน ลืม Key = ดูรหัสผ่านนั้นไม่ได้อีก

### กันการเขียนทับข้ามเครื่อง
- ทุกครั้งที่เขียนจะสุ่ม `ver` ใหม่ ใช้เป็นตัวระบุเวอร์ชัน (`base`) ว่าข้อมูลในเครื่องสร้างต่อจากเวอร์ชันไหนบนคลาวด์
- ตอนเขียนใช้ **Firestore transaction**: ถ้า `ver` บนคลาวด์ไม่ตรงกับ `base` แสดงว่ามีอุปกรณ์อื่นเขียนก่อน จึงยกเลิกการเขียน แล้วดึงเวอร์ชันนั้นมา merge ก่อนเขียนใหม่
- ขณะเปิดตู้อยู่ มี `onSnapshot` ฟังการเปลี่ยนแปลงแบบเรียลไทม์ อุปกรณ์อื่นแก้ไขเมื่อไหร่ รายการจะอัปเดตทันทีพร้อมแจ้งเตือน
- **Merge**: แต่ละรายการมีเวลาแก้ไขล่าสุด (`mt`) อันที่ใหม่กว่าชนะ การลบเก็บเป็น tombstone (เก็บไว้ 1 ปี) เพื่อไม่ให้รายการที่ลบแล้วกลับมา

### การกู้คืนจากข้อความสำรอง
ข้อความสำรองคือ JSON ของรายการ (รหัสผ่านยังเข้ารหัสด้วย Key ของแต่ละรายการ) กู้คืนแล้วจะแทนที่ทั้งข้อมูลในเครื่องและบนคลาวด์ อุปกรณ์อื่นจะ merge รายการที่ใหม่กว่าของตัวเองกลับเข้ามา

## หมายเหตุด้านความปลอดภัย
- CSP ใน `firebase.json` อนุญาตเฉพาะ gstatic/Google APIs/Google Fonts ถ้าเปลี่ยน `authDomain` เป็นโดเมนของตัวเอง ให้เพิ่มโดเมนนั้นใน `frame-src`
- Firebase SDK โหลดจาก `www.gstatic.com/firebasejs/10.14.1` ถ้าจะอัปเวอร์ชันให้แก้ค่า `FB` ใน `public/app.js`
- ไม่มี service worker ต้องออนไลน์ตอนเปิดหน้าเว็บ แต่ถ้าเน็ตหลุดระหว่างใช้งาน ยังแก้ไขต่อได้และจะซิงก์เมื่อเน็ตกลับมา
