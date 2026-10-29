// วาง config ของเว็บแอปจาก Firebase Console → Project settings → Your apps → SDK setup and configuration
// ถ้าปล่อยเป็น null และ deploy บน Firebase Hosting แอปจะดึง config เองจาก /__/firebase/init.json
export const firebaseConfig = null;
/* ตัวอย่าง
export const firebaseConfig = {
  apiKey: "AIza...",
  authDomain: "your-project.firebaseapp.com",
  projectId: "your-project",
  appId: "1:1234567890:web:abcdef",
};
*/
