# Opera Cookie Reader (Go)

โปรแกรมสำหรับอ่าน cookies จาก Opera browser บน Windows โดยใช้ภาษา Go

## คุณสมบัติ

- อ่าน cookies จาก Opera Stable
- Decrypt ค่า cookies ด้วย Windows DPAPI และ AES-GCM
- รองรับ encryption แบบใหม่ (v10/v11) และแบบเก่า
- บันทึกผลลัพธ์ลงไฟล์ `cookies.txt`

## ความต้องการ

- Windows OS
- Go 1.21 หรือสูงกว่า
- GCC compiler สำหรับ compile SQLite driver (ใช้ MinGW หรือ TDM-GCC)

## การติดตั้ง

1. ติดตั้ง Go จาก https://golang.org/dl/

2. ติดตั้ง GCC (ถ้ายังไม่มี):
   - ดาวน์โหลด TDM-GCC จาก https://jmeubank.github.io/tdm-gcc/
   - หรือใช้ MinGW

3. ดาวน์โหลด dependencies:
```bash
go mod download
```

## วิธีใช้งาน

1. **ปิด Opera browser ก่อนรันโปรแกรม** (เพื่อไม่ให้ database ถูกล็อค)

2. รันโปรแกรม:
```bash
go run opera_cookies.go
```

หรือ compile ก่อน:
```bash
go build opera_cookies.go
opera_cookies.exe
```

3. ผลลัพธ์จะถูกบันทึกในไฟล์ `cookies.txt`

## โครงสร้างโค้ด

- **decrypt()** - ใช้ Windows DPAPI สำหรับ decrypt ข้อมูล
- **getAESKey()** - อ่าน encryption key จาก Local State file
- **decryptValue()** - decrypt cookie value (รองรับทั้ง AES-GCM และ DPAPI)
- **main()** - อ่าน cookies จาก SQLite database และบันทึกผลลัพธ์

## คำเตือน

⚠️ **ข้อมูล cookies มีความละเอียดอ่อน**
- ไฟล์ `cookies.txt` ที่สร้างขึ้นมีข้อมูลสำคัญ
- กรุณาลบไฟล์ทิ้งหลังจากใช้งานเสร็จ
- ใช้เพื่อการศึกษาและทดสอบเท่านั้น

## ตัวอย่างผลลัพธ์

```
========================================
Host: .example.com
Name: session_id
Value: abc123xyz789
Path: /
Secure: true | HttpOnly: true
```

## การแก้ปัญหา

**ปัญหา: "ไม่พบไฟล์ Cookies"**
- ตรวจสอบว่าติดตั้ง Opera แล้ว
- ตรวจสอบ path: `%APPDATA%\Opera Software\Opera Stable\Cookies`

**ปัญหา: "database is locked"**
- ปิด Opera browser ก่อนรันโปรแกรม

**ปัญหา: "gcc not found"**
- ติดตั้ง GCC compiler (TDM-GCC หรือ MinGW)
- เพิ่ม GCC ใน PATH environment variable

## License

MIT License - ใช้เพื่อการศึกษาเท่านั้น
