# Kurulum ve güncelleme (kendi sunucunda Remyral)

Remyral’ın yönetim tarafı (konsol, API, veritabanı, kuyruk, yedekler) **tek bir Linux sunucuda** çalışır. Ajanlar
orada çalışmaz: kendi makinelerinde (Linux, macOS, Windows, Raspberry Pi) çalışırlar; makineler sunucuya dışarıya
doğru bağlanır. İngilizcesi: `docs/ops/selfhost-install.md` (her sürümde `INSTALL.md`).

## Gereksinimler

| | En az | Önerilen |
| --- | --- | --- |
| Sistem | Linux, x86_64 ya da aarch64 (Ubuntu 22.04+, Debian 12+, RHEL / Rocky / Alma 9+) | Ubuntu 24.04 LTS |
| İşlemci / bellek | 2 çekirdek, 4 GB | 4 çekirdek, 8 GB |
| Disk | 10 GB boş | 20 GB+ |
| Yazılım | Docker ≥ 24 ve compose eklentisi ≥ 2.24, OpenSSL ≥ 3, curl | — |
| Ağ | konsol için bir alan adı; 80 + 443 portları ya da kendi proxy’nin arkasında bir HTTPS portu | — |

**Windows ve macOS yönetim sunucusu olarak desteklenmez** (Docker Desktop dahil). İkisi de **makine** olarak tam
desteklenir: Makineler → Makine ekle.

## Kurulum

1. Alan adını (ör. `remyral.example.com`) sunucuya yönlendir.
2. Kurulum betiğini indir ve denetle. Resmi sürüm kanalı `https://releases.remyral.com/control-plane`; güncel
   sürüm **0.9.0** (ilk açık sürüm, 1.0’dan önce), **`9439dfaca133e249`** kimlikli sürüm anahtarıyla imzalı
   (anahtar kimliği GitHub’daki her sürüm duyurusunda da yazar):
   `curl -fsSLO https://releases.remyral.com/control-plane/0.9.0/install.sh`, sonra betiğin güvendiği anahtarın
   kimliği (`9439dfaca133e249` çıkmalı):
   `k="$(sed -n "s/^REMYRAL_TRUSTED_KEYS='\([^ ']*\).*/\1/p" install.sh)"; printf '%s=' "$k" | tr '_-' '/+' | base64 -d | sha256sum | cut -c1-16`
   Önce `--dry-run` ile dene: `sudo bash install.sh --dry-run --domain remyral.example.com --tls letsencrypt
   --email ops@example.com` (hiçbir şeyi değiştirmez, imzayı ve dosyaları doğrular). Kendi sürüm kanalın varsa
   `--release-url https://<sürüm-adresi>`.
3. Root olarak çalıştır, bir TLS biçimi seç:
   - Sunucu 80/443’te kendisi cevap verir, sertifikayı Let’s Encrypt verir:
     `sudo bash install.sh --domain remyral.example.com --tls letsencrypt --email ops@example.com`
   - Alan adı Cloudflare üzerinden: `--tls cloudflare` (SSL “Full”, origin sertifikasıyla “Full (strict)”:
     `--tls-cert origin.pem --tls-key origin.key`)
   - Kendi ters proxy’n TLS’i bitirir: `--tls proxy --https-port 8443 --http-port 8080 --bind 10.0.0.5
     --trusted-proxy 10.0.0.2/32`

   Diğer seçenekler: `--data-dir` (varsayılan `/var/lib/remyral`), `--version`, `--registry` (kendi aynan),
   `--bundle <klasör>` (çevrimdışı kurulum), `--backup-recipient age1…` (yedekler anahtar dosyalarını da şifreli
   taşır), `--no-update-check`, `--dry-run` (her adımı gösterir, hiçbir şeyi değiştirmez), `--yes`.
4. Betik ne yapar: gereksinimleri kontrol eder; sürümü indirip **imzasını ve her dosyasını doğrular** (doğrulama
   tutmazsa hiçbir şeye dokunmadan durur); veri klasörünü kurar; parolaları ve anahtar dosyalarını bir kez üretir (asla
   ekrana yazmaz); proxy ayarını yazar; imajları **özet (digest) ile** çeker; veritabanını taşır; sistemi başlatır;
   sağlık kontrolünü bekler; **tek kullanımlık kurulum anahtarını** bir kez gösterir.
5. `https://remyral.example.com/setup` adresini aç, anahtarı gir, sahip hesabının kullanıcı adını ve parolasını seç.
   Sonra giriş yap: ilk girişte authenticator uygulamasını bağlarsın ve 10 kurtarma kodu alırsın — telefondan başka
   bir yerde sakla.
6. **Kurulum sihirbazı** açılır: organizasyon adı, alan adı ve erişim, güvenlik ayarı, ilk makine (her sistem için
   kurulum komutu), git bağlantısı, isteğe bağlı entegrasyonlar, ilk proje ve örnek iş (“README özetle”) — 9 adım,
   sonda “Hazırsın”. Her adım atlanabilir; sonra Ana sayfa → “Kurulumu tamamla”dan devam edersin.

**Güvenlik ayarı** adımında üç hazır ayardan birini seçersin; yeni kurulum **Dengeli** ile başlar:

- **Dengeli** (varsayılan): kod 4 saat geçerli. Güvenlik çekirdeğine ek olarak kimlik bilgileri, oturum açma, sandbox,
  makine yönetimi, üretim deploy’u, entegrasyonlar, sürümler ve MCP kurulumu authenticator kodu ister. Deploy, force
  push, çalışma alanı dışı silme ve gizli okuma yine bir insana sorulur; otomatik mod kapalıdır.
- **Serbest**: kod 12 saat geçerli ve “bu cihazı hatırla” ile girişteki tek kod bütün oturumu kapsar. Yalnız güvenlik
  çekirdeği (güvenlik ayarları, 2FA, kullanıcı ve rol değişiklikleri, sırları açık göstermek) kod ister; **makine
  yönetimini açmak, sandbox’ı kaldırmak, makine onaylamak, üretim deploy’u, kimlik bilgileri ve entegrasyonlar kod
  istemez**, otomatik mod deploy dahil onayları kendiliğinden geçirir. Ele geçirilmiş bir oturum bunların hepsini kodsuz
  yapabilir: yalnız tek kişilik, kapalı bir kurulumda seç.
- **Sıkı**: her ayrıcalıklı işlem kısa süre içinde (varsayılan 10 dakika) kod ister, otomatik onay yoktur, asistan
  yalnız kart hazırlar.

Bu adım ve Ayarlar → Güvenlik aynı ayarı değiştirir. Varsayılan yalnızca yeni kurulumlar içindir; bir güncelleme
seçilmiş ayarı hiçbir zaman değiştirmez.

**Alan adı ve erişim** adımında konsolun genel adresini, o adresin sunduğu TLS sertifikasını (ne zamana kadar
geçerli; “Sertifikayı şimdi denetle”) ve konsolu şu an o adresten açıp açmadığını görürsün; **alan adını da buradan
değiştirirsin, terminale gerek yok**:

1. Yeni adın DNS kaydını (A ya da AAAA) sunucuya yönlendir.
2. Alan adını yaz, sertifika ve bağlantı türünü seç (Let’s Encrypt ve e-postası / Cloudflare arkasında / kendi vekil
   sunucun) ve “DNS’i denetle” ile adın bu sunucuyu gösterip göstermediğine bak.
3. “Kaydet ve uygula” (güvenlik ayarın isterse authenticator kodu). Sunucu, master’ın imzaladığı isteği kendisi uygular
   (`remyral-ctl apply-pending`, kurulumun kurduğu bir systemd birimi): vekil sunucuyu yeni ada çevirir, sertifikayı alır,
   sağlığı denetler. Yeni ad sağlıklı olana kadar eski adres çalışır (sonra bir saat daha); 5 dakikada sağlıklı olmazsa
   eski ada kendiliğinden döner. Sihirbaz “Uygulanıyor… / Hazır / Hata: …” diye gösterir.

Sunucu bu istekle yalnızca alan adını, TLS türünü ve Let’s Encrypt e-postasını değiştirebilir; başka hiçbir komut
çalıştırmaz. Son değişikliği `sudo remyral-ctl status` gösterir. remyral-ctl ile kurulmamış kurulumlarda (yönlendirmeyi
Coolify gibi başka bir platform yapıyorsa) “Kaydet” yalnızca bağlantıların kullandığı adresi değiştirir; sihirbaz o
platformda neyin yönlendirilmesi gerektiğini yazar.

Kurulum anahtarını hesap oluşturmadan kaybettiysen: `sudo remyral-ctl setup-token`. Betiği yeniden çalıştırmak
güvenlidir; ilk çalışmanın parolalarını ve seçimlerini korur.

## Güncelleme

Yeni imzalı bir sürüm çıktığında sahipler konsolda **“Güncelleme mevcut”** bandını görür (Notlar: sürüm notları,
uyumsuz değişiklikler, komut). Güncelleme her zaman sunucuda yapılır:

- `sudo remyral-ctl upgrade --check` — yeni sürüm var mı?
- `sudo remyral-ctl upgrade --dry-run` — adımları göster
- `sudo remyral-ctl upgrade [--to 1.3.0]` — doğrula → çek → master’ı durdur → **yedek al** → taşı → başlat →
  sağlık kontrolü

Sağlık kontrolü geçmezse: veritabanı şeması değişmediyse eski sürüm kendiliğinden geri gelir. Şema ilerlediyse yeni
sürüm durur (eski sürüm yeni şemayla açılmaz) ve komut geri dönüşü yazar:
`sudo remyral-ctl rollback --to 1.2.0 --restore-backup <yedek kimliği>` — güncelleme öncesi yedeği geri yükler (eski
veritabanı `remyral_replaced_<zaman>` adıyla saklanır).

`sudo remyral-ctl status` sürümü, şemayı, kapsayıcıları ve güncelleme durumunu gösterir; `sudo remyral-ctl doctor`
tanılama kontrollerini sunucudan çalıştırır (makinelerle tam tanılama: Ayarlar → Tanılama).

## Yedek ve geri yükleme

- Yedek servisi her gece veritabanını yedekler ve geri yükleme provası yapar; durum Ayarlar → Yedekler’de. Elle yedek:
  `sudo remyral-ctl backup`.
- `<veri>/stack.env` ve `<veri>/secrets/` klasörünü sunucunun dışında (parola yöneticisi) sakla: `totp.key` olmadan
  herkes authenticator’ını yeniden bağlamak zorunda kalır.
- Aynı sunucuda geri yükleme: `sudo remyral-ctl rollback --to <sürüm> --restore-backup <kimlik>`. Yeni sunucuya taşıma:
  `docs/ops/backup-restore.md` §5.

## Kaldırma

- `sudo remyral-ctl uninstall` — kapsayıcıları kaldırır, veri klasörü kalır.
- `sudo remyral-ctl uninstall --purge-data` — veritabanını, yedekleri ve anahtarları da siler (geri alınamaz).

## Yayıncı tarafı

Bir sürümü yayınlamak (imajlar, imzalı paket, besleme): `docs/ops/selfhost-release.md`. İlk herkese açık sürüm için
kontrol listesi oradadır.
