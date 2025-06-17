# Proje Yönetim Sistemi

Bu web tabanlı uygulama, okullar veya kurumlar için proje takibi, takım yönetimi ve kaynak (malzeme) yönetimini kolaylaştırmak amacıyla geliştirilmiş kapsamlı bir proje yönetim sistemidir. Öğrencilerin, öğretmenlerin ve yöneticilerin proje süreçlerini tek bir platform üzerinden verimli bir şekilde yönetmelerini sağlar.

## 🚀 Özellikler

- **Kullanıcı Rolleri:**
  - **Admin:** Sistemi yönetir, kullanıcıları ekler/siler.
  - **Kurum Yöneticisi:** Öğretmenleri, yarışma şablonlarını ve malzeme envanterini yönetir. Malzeme taleplerini onaylar/reddeder.
  - **Öğretmen:** Takımlara danışmanlık yapar, proje ilerlemesini izler ve malzeme taleplerini ön onaya gönderir.
  - **Öğrenci:** Takımlara katılır, projeler oluşturur, görevleri tamamlar ve malzeme talebinde bulunur.
- **Proje Yönetimi:**
  - Proje oluşturma, düzenleme ve silme.
  - Görev takibi (tamamlandı/tamamlanmadı).
  - Proje ilerlemesini yüzde olarak gösterme.
  - Proje zaman çizelgesi oluşturma ve önemli tarihleri işaretleme.
- **Takım Yönetimi:**
  - Öğretmenler tarafından takım oluşturma.
  - Takımlara öğrenci ekleme/çıkarma.
- **Malzeme Yönetimi:**
  - Kurum yöneticisi tarafından malzeme envanteri oluşturma.
  - Öğrenciler tarafından projeler için malzeme talebi oluşturma.
  - Çok aşamalı onay süreci (Öğretmen -> Kurum Yöneticisi).
  - Harici (satın alınacak) malzeme talepleri oluşturma.
- **Yarışma Şablonları:**
  - Kurum yöneticileri tarafından TEKNOFEST, TÜBİTAK gibi yarışmalar için özel şablonlar oluşturma.
  - Şablonlara özel takvimler ve gerekli dokümanlar ekleme.
  - Projeleri bu şablonlara göre başlatma.
- **Kimlik Doğrulama:**
  - E-posta/şifre ile standart kayıt ve giriş.
  - Google ile OAuth2.0 üzerinden güvenli giriş.
  - E-posta doğrulama ve şifre sıfırlama mekanizması.
- **Raporlama ve Bildirimler:**
  - Proje durumu, malzeme kullanımı ve diğer metrikler hakkında raporlar (Kurum Yöneticisi paneli).
  - E-posta ile otomatik bildirimler (kayıt, onay, talep vb.).
- **Dosya Yönetimi:**
  - Projelere özel dosya ve resim yükleme.

## 🛠️ Teknoloji Yığını

- **Backend:** Python, Flask
- **Veritabanı:** SQLAlchemy, SQLite
- **Frontend:** HTML, CSS, JavaScript, Bootstrap
- **Kimlik Doğrulama:** Flask-Login, Flask-Bcrypt, Authlib (Google OAuth)
- **E-posta:** Flask-Mail
- **Diğer Kütüphaneler:** Flask-APScheduler, WeasyPrint (PDF Raporlama), Pillow (Resim işleme)

## ⚙️ Kurulum ve Başlatma

1.  **Depoyu Klonlayın:**
    ```bash
    git clone https://github.com/kullanici-adiniz/proje-yonetim-sistemi.git
    cd proje-yonetim-sistemi
    ```

2.  **Sanal Ortam Oluşturun ve Aktif Edin:**
    ```bash
    python -m venv venv
    # Windows için:
    venv\Scripts\activate
    # macOS/Linux için:
    source venv/bin/activate
    ```

3.  **Gerekli Paketleri Yükleyin:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Yapılandırma Dosyalarını Oluşturun:**
    - `credentials.json`: Google OAuth ve Gemini API anahtarlarınızı bu dosyaya ekleyin. Örnek bir `credentials.json.example` dosyası oluşturulabilir.
    - `mail_info.json`: E-posta sunucu bilgilerinizi (SMTP) bu dosyaya ekleyin.

5.  **Veritabanını Oluşturun:**
    Uygulamayı ilk kez çalıştırdığınızda `site.db` adında bir veritabanı dosyası otomatik olarak oluşturulacaktır. Alternatif olarak, bir Flask shell içerisinde veritabanını oluşturabilirsiniz:
    ```python
    from app import create_tables
    create_tables()
    ```

6.  **Admin Kullanıcısı Oluşturun:**
    İlk admin kullanıcısını oluşturmak için `create_admin.py` betiğini çalıştırın:
    ```bash
    python create_admin.py
    ```

7.  **Uygulamayı Çalıştırın:**
    ```bash
    flask run
    # veya
    python app.py
    ```
    Uygulama varsayılan olarak `http://127.0.0.1:5000` adresinde çalışacaktır.

## 📖 Kullanım

- **Admin** olarak giriş yapıp `Kurum Yöneticisi` rolünde kullanıcılar oluşturun.
- **Kurum Yöneticisi** olarak giriş yapıp `Öğretmen` rolünde kullanıcılar oluşturun ve yarışma şablonları, malzemeler gibi başlangıç verilerini sisteme girin.
- **Öğretmen** olarak giriş yapıp takımlarınızı oluşturun ve öğrencilerinizi takımlara davet edin.
- **Öğrenciler** kayıt olup takımlara katıldıktan sonra projelerini oluşturmaya başlayabilirler. 
