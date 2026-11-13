-- جدول الحسابات فقط. لا توجد أي جداول أخرى (لا طلبات ولا محتوى).
CREATE TABLE IF NOT EXISTS users (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name          VARCHAR(40)  NOT NULL,
  email         VARCHAR(254) NOT NULL,
  password_hash VARCHAR(100) NOT NULL,          -- bcrypt hash فقط، وليس كلمة المرور
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- منع تكرار البريد الإلكتروني (بدون حساسية لحالة الأحرف)
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_uq ON users (lower(email));
