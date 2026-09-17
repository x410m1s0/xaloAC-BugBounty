# xaloAC

**Yetkili bug bounty araştırmaları için yerel çalışan reconnaissance, tarama ve bulgu yönetim platformu.**

- **Marka:** xaloAC
- **Sahip / yazar:** x410m1s0
- **Çalışma modeli:** Local-first, SQLite tabanlı
- **Arayüz:** Türkçe / English
- **Lisans:** [xaloAC Özel Lisansı](./LICENSE)

> xaloAC yalnızca açıkça yetkilendirilmiş hedeflerde kullanılmalıdır. Yetkisiz tarama, erişim denemesi, veri çıkarma veya hizmet kesintisine yönelik kullanım yasaktır.

## 1. xaloAC ne yapar?

xaloAC, izinli bir bug bounty veya güvenlik değerlendirmesi kapsamındaki araştırmayı tek bir yerel çalışma alanında toplar:

- Program ve izinli scope yönetimi
- HTTPS tabanlı, düşük etkili crawl ve pasif analiz
- HTML linkleri, form action'ları ve JavaScript endpoint referansları keşfi
- HTTP güvenlik başlıkları, cookie bayrakları, CORS, TLS ve yaygın yapılandırma sinyalleri
- Kontrollü active plugin'leri (XSS, CORS ve diğer kayıtlı kontroller) yetki onayıyla çalıştırma
- Bulgu kaydı, severity, kanıt, tekrar adımları ve fingerprint
- SQLite scan history ve bulgu deduplication
- Rapor önizleme, panoya kopyalama ve JSON export
- CLI ve web arayüzünde ortak tarama motoru

xaloAC bir anonimlik, gizlenme veya exploit otomasyonu aracı değildir. Hedef sistem kaynak IP'yi, zamanı ve istek davranışını görebilir.

## 2. Gereksinimler

- Windows, macOS veya Linux
- **Node.js 22 veya üzeri**
- Açıkça izin verilmiş bir HTTPS hedef
- Browser testleri için Playwright Chromium

Node sürümünü kontrol etmek için:

```powershell
node --version
```

## 3. Windows'ta başlatma

En kolay yöntem proje klasöründeki **`run-xaloac.bat`** dosyasına çift tıklamaktır.

Batch dosyası:

1. Proje klasörüne geçer.
2. Node.js'in kurulu ve major sürümün en az 22 olduğunu kontrol eder.
3. Gerekirse `package-lock.json` ve npm bağımlılıklarını hazırlar.
4. Gerekirse Playwright Chromium'u kurar.
5. `npm run check` ile JavaScript dosyalarını kontrol eder.
6. Tarayıcıyı `http://127.0.0.1:4173` adresinde açar.
7. Yerel xaloAC sunucusunu başlatır.

Elle başlatmak için:

```powershell
npm install
npx playwright install chromium
npm start
```

Ardından tarayıcıda:

```text
http://127.0.0.1:4173
```

Sunucuyu durdurmak için çalışan terminal penceresinde `Ctrl+C` kullanın.

## 4. İlk çalışma akışı

### 4.1 Program ve scope ekleme

1. **Hedefler & Scope** ekranını açın.
2. Program adını ve platform/şirket bilgisini girin.
3. Her satıra bir host veya URL olacak şekilde izinli varlıkları girin.
4. Program politikasındaki `In scope`, `Rules`, `Safe harbor`, rate limit ve otomasyon koşullarını okuyun.
5. **Programı kaydet** düğmesine basın.

Scope dışı varlıkları tahmin ederek eklemeyin. Wildcard değerlerini programın yayınladığı biçimde kullanın.

### 4.2 Crawl başlatma

1. HTTPS başlangıç URL'sini girin.
2. **Scope tara** düğmesine basın.
3. xaloAC yalnızca scope güvenlik kontrollerinden geçen düşük etkili istekler gönderir.
4. Sonuçlar SQLite'a kaydedilir.
5. Güvenlik sinyalleri **Bulgular** ekranında taslak olarak görünür.
6. Her sinyali program kurallarına göre manuel doğrulayın.

### 4.3 Bulgu hazırlama

Bir bulgu için mümkün olduğunca şu alanları tamamlayın:

- Başlık
- Severity
- Etkilenen asset veya endpoint
- Kısa ve ölçülebilir özet
- Tekrar adımları
- Hassas veri içermeyen kanıt notu
- Etki ve düzeltme önerisi

Otomatik sinyal tek başına doğrulanmış güvenlik açığı değildir. Rapor göndermeden önce manuel doğrulama yapın.

### 4.4 Rapor oluşturma

**Rapor merkezi**, seçilen bulgunun özetini, asset bilgisini, tekrar adımlarını, kanıtını ve önerilen düzeltmeyi gösterir. **Raporu kopyala** ile metni bug bounty platformuna taşıyabilirsiniz.

## 5. Web arayüzü

Web arayüzü:

- Türkçe ve English dil seçimi sunar.
- Dil seçimini tarayıcıda hatırlar.
- Program ve bulgu verisini doğrudan API üzerinden SQLite'tan okur.
- Tarayıcı yenilense bile kayıtları `.data/xaloac.db` üzerinden yeniden yükler.
- Tema düğmesiyle aydınlık ve koyu görünüm arasında geçiş yapar.
- Workspace export ile mevcut görünümün JSON yedeğini indirir.

Arayüz verileri için `localStorage` ana veri kaynağı değildir. Kalıcı kayıt sunucu tarafındaki SQLite veritabanındadır.

## 6. CLI kullanımı

Tekrarlanabilir assessment için:

```powershell
npm run assess -- --url https://target.example --max-pages 50 --delay-ms 500 --markdown --html --out .\reports
```

CLI çıktıları:

- JSON: ham tarama, endpoint, teknoloji, finding ve evidence verileri
- Markdown: araştırma notları ve triage için rapor
- HTML: tarayıcıda açılabilen bağımsız rapor

CLI workspace komutları:

```powershell
npm run assess -- program create --name "Acme Program" --policy-url https://example.com/rules
npm run assess -- program list --json
npm run assess -- scope add --program-id <id> --value "*.example.com"
npm run assess -- scope add --program-id <id> --value admin.example.com --exclude
npm run assess -- scope list --program-id <id> --json
npm run assess -- scan list --json
npm run assess -- finding list --json
```

## 7. API özeti

Sunucu yalnızca localhost üzerinde dinler.

| Method | Endpoint | Açıklama |
| --- | --- | --- |
| GET | `/health` | Engine sağlık kontrolü |
| GET | `/api/programs` | Program ve scope listesi |
| POST | `/api/programs` | Program oluşturma |
| GET | `/api/findings` | Bulgu listesi |
| POST | `/api/findings` | Manuel bulgu oluşturma |
| GET | `/api/findings/:id` | Bulgu detayı |
| GET | `/api/findings/:id/risk` | Risk değerlendirmesi |
| POST | `/api/findings/:id/report` | Markdown, HTML veya JSON rapor |
| POST | `/api/scan` | Senkron düşük etkili crawl |
| POST | `/api/jobs` | Asenkron scan job oluşturma |
| GET | `/api/jobs/:id` | Job durumunu okuma |
| DELETE | `/api/jobs/:id` | Job iptali |
| GET | `/api/scans` | Scan geçmişi |
| GET | `/api/scans/:id/requests` | Request geçmişi |
| GET | `/api/scans/:id/endpoints` | Endpoint envanteri |
| POST | `/api/active` | Yetki onaylı active kontroller |
| POST | `/api/replay` | Yetki onaylı, scope tekrar kontrollü replay |

Active test ve replay isteklerinde `authorizationConfirmed: true` zorunludur.

## 8. Güvenlik ve gizlilik sınırları

- Sunucu varsayılan olarak `127.0.0.1` üzerinde dinler.
- Telemetry ve üçüncü taraf analytics yoktur.
- Harici CDN veya font yüklenmez.
- Browser cookie/session bilgisi otomatik olarak tarama isteklerine eklenmez.
- Auth profilleri hassas değerleri redacted metadata olarak saklar.
- Private/link-local IP ve scope dışı hedef kontrolleri bulunur.
- Destructive method, brute force, credential stuffing ve exploit confirmation amacıyla tasarlanmamıştır.
- Tüm hedeflerde ilgili programın yazılı izin ve rate limit koşulları esas alınmalıdır.

Yerel çalışması, aracı anonim yapmaz. VPN, proxy, Tor veya attribution gizleme özelliği sunulmaz.

## 9. Proje yapısı

```text
.
├─ active/             Active kontrol plugin'leri
├─ browser/            Playwright browser engine
├─ discovery/          OpenAPI ve GraphQL keşfi
├─ lab/                Yalnızca localhost disposable test hedefi
├─ test/               Node.js test suite'i
├─ app.js              Web arayüzü ve API istemcisi
├─ server.js           Local HTTP server ve API router
├─ scanner.js          Crawl ve pasif analiz motoru
├─ storage.js          SQLite şema, migration ve persistence
├─ finding.js          Bulgu sözleşmesi, redaction ve fingerprint
├─ scope.js            Scope include/exclude kontrolleri
├─ job-manager.js      Asenkron job lifecycle
├─ run-xaloac.bat      Windows başlatıcı
├─ index.html          Web arayüzü
├─ styles.css          Arayüz stilleri
├─ LICENSE             xaloAC özel lisansı
└─ .data/              Yerel SQLite verisi; Git'e alınmaz
```

## 10. Test ve doğrulama

Syntax kontrolü:

```powershell
npm run check
```

Test suite:

```powershell
npm test
```

Sağlık kontrolü:

```powershell
Invoke-WebRequest http://127.0.0.1:4173/health
```

Beklenen health yanıtı `ok: true` içeren JSON'dur.

## 11. Veri ve yedekleme

Varsayılan SQLite dosyası:

```text
.data\xaloac.db
```

Bu klasör `.gitignore` içindedir. Çalışma verisini yedeklemek için web arayüzündeki **Workspace export** düğmesini kullanın. `.data` klasörünü silmek tüm yerel program, tarama ve bulgu geçmişini siler.

## 12. Lisans ve marka

xaloAC, x410m1s0 tarafından sahip olunan özel lisans ile dağıtılır. Bu proje MIT, Apache-2.0, GPL veya benzeri açık kaynak lisanslarından biri değildir. İzin verilen ve yasaklanan kullanımlar için [LICENSE](./LICENSE) dosyasına bakın.

