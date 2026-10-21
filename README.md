# TR + KSA RP Forum

Gerçek veritabanı ve Google OAuth kullanan Flask RP forumu.

## 1) Supabase
- Yeni bir Supabase projesi açın.
- SQL Editor'e `schema.sql` içeriğini yapıştırıp çalıştırın.
- Project URL ve Service Role Key değerlerini environment variables olarak ekleyin.

## 2) Google OAuth
Google Cloud Console'da OAuth Client oluşturun.
Authorized redirect URI:
`https://SITENIZ/auth/callback`

Local:
`http://127.0.0.1:5000/auth/callback`

Google client ID ve secret'ı environment variables olarak ekleyin.

## 3) Root Owner
Root Owner hesabı kodda:
`alikayahd041@gmail.com`

Bu hesap normal rol tablosuna yazılmaz. Uygulama tarafında özel Root Owner olarak tanınır.

## 4) Çalıştırma
pip install -r requirements.txt
python app.py

Production:
gunicorn app:app
