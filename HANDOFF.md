# ตู้นิรภัยรหัสผ่าน — งานต่อ: เชื่อม Firebase

## สถานะปัจจุบัน
`vault.html` เป็นไฟล์เดียว ไม่มี dependency ใช้งานได้แล้ว:
- เข้ารหัสในเบราว์เซอร์ด้วย WebCrypto: PBKDF2-SHA256 600,000 รอบ → AES-256-GCM
- vault ทั้งก้อนเข้ารหัสเป็น blob เดียว: `{v:1, iter, salt, iv, ct}` (base64) เก็บใน `localStorage["vault.v1"]`
- IV สุ่มใหม่ทุกครั้งที่บันทึก, salt คงที่ต่อ vault
- ฟีเจอร์: ตั้ง/ปลดล็อก Master Key, เพิ่ม/แก้/ลบ/ค้นหา, คัดลอกคลิกเดียว, สุ่มรหัส, ล็อกอัตโนมัติ 5 นาที, สำรอง/กู้คืนเป็นข้อความ
- หมายเหตุ: ไฟล์เขียนมาสำหรับ artifact ซึ่งเติม `<!doctype html><head>…<body>` ให้อัตโนมัติ เมื่อใช้งานเองให้ห่อด้วยโครง HTML ปกติและใส่ `<meta charset="utf-8">` + viewport meta

## เป้าหมาย
ซิงก์ blob ที่เข้ารหัสแล้วข้ามอุปกรณ์ผ่าน Firebase โดย **Master Key ไม่ออกจากเบราว์เซอร์เด็ดขาด** (zero-knowledge)

## ข้อกำหนด
1. Firebase Auth (Google sign-in) ใช้ระบุตัวตนเพื่อดึงข้อมูลเท่านั้น — แยกจาก Master Key
2. Firestore เก็บเฉพาะ `users/{uid}` → `{v, iter, salt, iv, ct, updatedAt}` ห้ามมี plaintext, Key หรือ hash ของ Key
3. Security Rules: อ่าน/เขียนได้เฉพาะ `request.auth.uid == uid`
4. ใช้ localStorage เป็น cache ออฟไลน์ต่อไป; ตอนบันทึกให้เขียนทั้ง local และ Firestore
5. กันการเขียนทับข้ามเครื่อง: เช็ค `updatedAt` (หรือใช้ transaction) ก่อนเขียน ถ้า remote ใหม่กว่าให้ดึงมาถอดรหัสและ merge/แจ้งผู้ใช้
6. Deploy บน Firebase Hosting, Firebase JS SDK แบบ modular
7. คงฟีเจอร์และหน้าตาเดิมทั้งหมด UI ภาษาไทย

## สิ่งที่ต้องส่งมอบ
- `public/index.html` (+ ไฟล์ JS แยกได้)
- `firestore.rules`, `firebase.json`
- README ขั้นตอน: สร้างโปรเจกต์, เปิด Auth/Firestore, ใส่ config, `firebase deploy`

## ห้าม
- ส่ง Master Key หรือ plaintext ขึ้นเครือข่าย
- ลดจำนวนรอบ PBKDF2
- ใช้ IV ซ้ำ

## เปลี่ยนแปลงภายหลัง (2026-10-29, เจ้าของโปรเจกต์ตัดสินใจ)
- ตัด Master Key ออก เข้าด้วยบัญชี Google อย่างเดียว เพื่อให้ดูรายชื่อผู้ใช้และแบนได้ (`banned/{uid}`)
- ชื่อเว็บ username และโน้ต เก็บบน Firestore แบบอ่านได้ (`users/{uid}` → `{v:4, data, ver, updatedAt}`) รหัสผ่านเข้ารหัสในเบราว์เซอร์ด้วย Key ของแต่ละรายการ
- ข้อ "ห้ามส่ง plaintext ขึ้นเครือข่าย" จึงเหลือความหมายว่า ห้ามส่งรหัสผ่านจริงหรือ Key ของรายการ ส่วนการห้ามลดรอบ PBKDF2 และห้ามใช้ IV ซ้ำยังใช้เหมือนเดิม
- ฐานข้อมูลถูกล้างเริ่มใหม่ตอนเปลี่ยน (ไม่มีการย้ายข้อมูลจากรุ่น Master Key)
