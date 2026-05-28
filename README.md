# Hala9 — Production Mode / وضع الإنتاج

> **Ready-to-deploy barbershop queue management system**  
> **نظام إدارة طوابير الحلاقة جاهز للنشر**

---

## English

### 📖 About

This is the **production build** of Hala9. Unlike the development version, the frontend is pre-compiled (inside `client/`) and served directly by Flask — no Vite dev server required. Deploy as-is on any server that supports Python 3.11+.

### 📦 What's Included

| Path | Description |
|------|-------------|
| `app.py` | Main Flask application (all API routes + static serving) |
| `database.py` | SQLite database helper (schema, connections, WAL mode) |
| `utils.py` | Input sanitization with bleach |
| `routes/admin.py` | Admin API blueprint (login, logout, CRUD, stats) |
| `routes/scp.py` | System Control Panel kill switch blueprint |
| `client/` | **Built frontend** — compiled SPA (React) |
| `client/index.html` | Entry point for the SPA |
| `client/assets/` | Compiled JS/CSS bundles |
| `client/icons/` | PWA icons |
| `client/manifest.json` | PWA manifest |
| `client/stope.html` | Kill switch page (bilingual) |
| `queue.db` | SQLite database |
| `cleanDB.py` | Reset database script |
| `requirements.txt` | Python dependencies |
| `SCP_USAGE.md` | SCP kill switch documentation |

### 🚀 Deployment

```bash
# Install dependencies
pip install -r requirements.txt

# Run (single command, serves everything on :5000)
python app.py
```

- The frontend is served at `/`
- The API is at `/api/*`
- Admin login: `admin` / `admin123`
- No build step needed — frontend is pre-compiled

### 🔒 Environment Variables

| Variable | Description |
|----------|-------------|
| `FLASK_SECRET_KEY` | Flask secret key (auto-generated if unset) |
| `FLASK_DEBUG` | Set to `1` for debug logs (insecure, warns in logs) |
| `FRONTEND_URL` | CORS origin for production (e.g. `https://example.com`) |

### ⚙️ SCP Kill Switch

Emergency system shutdown via API. See `SCP_USAGE.md` for details.

---

## العربية

### 📖 عن هذا المجلد

هذه هي **نسخة الإنتاج** من تطبيق حلقة. على عكس نسخة التطوير، الواجهة الأمامية مُجمَّعة مسبقاً (داخل `client/`) ويتم تقديمها مباشرة عبر Flask — بدون الحاجة إلى خادم Vite. انسخ المجلد كما هو على أي خادم يدعم Python 3.11+.

### 📦 محتويات المجلد

| المسار | الوصف |
|--------|-------|
| `app.py` | تطبيق Flask الرئيسي (جميع مسارات API + تقديم الملفات الثابتة) |
| `database.py` | مساعد قاعدة بيانات SQLite (الهيكل، الاتصالات، وضع WAL) |
| `utils.py` | تنقية المدخلات باستخدام bleach |
| `routes/admin.py` | مخطط API الإدارة (تسجيل الدخول، CRUD، الإحصائيات) |
| `routes/scp.py` | مخطط مفتاح الإيقاف الطارئ (SCP) |
| `client/` | **الواجهة الأمامية المُجمَّعة** — تطبيق React | |
| `client/index.html` | نقطة الدخول لتطبيق الصفحة الواحدة |
| `client/assets/` | حزم JS/CSS المُجمَّعة |
| `client/icons/` | أيقونات PWA |
| `client/manifest.json` | بيان PWA |
| `client/stope.html` | صفحة الإيقاف الطارئ (ثنائية اللغة) |
| `queue.db` | قاعدة بيانات SQLite |
| `cleanDB.py` | سكريبت إعادة تعيين قاعدة البيانات |
| `requirements.txt` | مكتبات Python |
| `SCP_USAGE.md` | توثيق مفتاح الإيقاف الطارئ |

### 🚀 النشر

```bash
# تثبيت المكتبات
pip install -r requirements.txt

# التشغيل (أمر واحد، يخدم كل شيء على :5000)
python app.py
```

- الواجهة الأمامية تُقدم على المسار `/`
- API على المسار `/api/*`
- بيانات الدخول الافتراضية: `admin` / `admin123`
- لا حاجة لخطوة بناء — الواجهة مُجمَّعة مسبقاً

### 🔒 متغيرات البيئة

| المتغير | الوصف |
|---------|-------|
| `FLASK_SECRET_KEY` | مفتاح Flask السري (يُولد تلقائياً إذا لم يُضبط) |
| `FLASK_DEBUG` | ضبط على `1` لتسجيل التصحيح (غير آمن، يُحذر في السجلات) |
| `FRONTEND_URL` | نطاق CORS للإنتاج (مثال: `https://example.com`) |

### ⚙️ مفتاح الإيقاف الطارئ (SCP)

إغلاق طارئ للنظام بالكامل عبر API. راجع `SCP_USAGE.md` للتفاصيل.
