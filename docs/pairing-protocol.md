# Eşleştirme protokolü — v1 (yerel ağ)

**Durum:** CLI tarafı uygulandı (`cli/internal/pairing`, `cli/internal/envelope`,
25 Eylül 2026). Telefon tarafı (`packages/pairing_client`) Faz 2b. Enroll
uzantısı (17 Ekim 2026): `cli/internal/enroll`, `pairing_client`'ta
`PairingEnrollment`.
**Kapsam:** aynı ağdaki doğrudan HTTP yolu ve onu bulmak için mDNS. Relay'e
düşme bu sözleşmenin üstüne gelir, mesajları değiştirmez.

Bu belge iki taraf arasındaki sözleşmedir. Dart tarafı buradaki her baytı
aynı üretmek zorunda; Go testleri (`envelope_test.go`, `server_test.go`)
referans uygulamadır.

## Tehdit modeli, kısaca

- Ağdaki herkes her isteği görür ve değiştirebilir (HTTP, TLS yok).
- QR yalnızca ekrandan telefona gider. Ama omuz üstünden görülebilir, bu
  yüzden QR'ın sızması tek başına zarfı ele geçirmeye yetmemeli.
- Masaüstündeki kullanıcı iki ekrandaki 6 haneyi karşılaştırır ve onaylar.

## Sabitler

| Ad | Değer |
|---|---|
| Oturum kimliği `sid` | 16 rastgele bayt |
| QR sırrı `k` | 32 rastgele bayt — **ağa hiç çıkmaz** |
| Nonce'lar | 32 rastgele bayt |
| El sıkışma süresi | QR göründükten sonra **60 sn** (talep + açıklama) |
| Karar süresi | SAS göründükten sonra **60 sn** |
| Base64 | URL-safe, **dolgusuz** (`RawURLEncoding`) |

## QR

```
portlight://pair?v=1&sid=<b64 sid>&k=<b64 k>&a=<ip>:<port>[,<ip>:<port>…]
```

`a` en çok 4 adres taşır, tercih sırasıyla: varsayılan rotanın adresi, sonra
ayağa kalkmış arayüzlerdeki diğer özel IPv4'ler. Loopback, noktadan noktaya
(VPN tünelleri) ve sanal kartlar (WSL/Hyper-V `vEthernet`, Docker, VM) hariç.
Telefon adresleri sırayla dener.

## mDNS (yedek)

Adreslerin hiçbirine ulaşılamazsa telefon DNS-SD ile arar:

| Alan | Değer |
|---|---|
| Servis | `_portlight._tcp.local.` |
| Örnek adı | `portlight-<tag>` |
| TXT | `v=1`, `tag=<tag>` |
| `tag` | `hex(SHA256("portlight/pair/v1/mdns" ‖ 0x00 ‖ sid)[0:8])` — **uzunluk öneki yok** |

İlan ne makine adını ne `sid`'i açık eder; telefon `tag`'i QR'daki `sid`'den
hesaplayıp eşleşen örneğin adres/portuna gider. mDNS ilanı başarısız olursa
CLI uyarı basıp doğrudan yolla devam eder.

## Relay (son yedek)

Telefon ile masaüstü birbirine hiç ulaşamıyorsa (farklı ağ, istemci
izolasyonu) aynı üç mesaj bir **posta kutusu relay'i** üzerinden gider.
Relay mesajları anlamaz, yalnız kutu taşır. CLI relay'i LAN sunucusuyla
**aynı anda** dinler; aynı oturum durum makinesi, hangi yoldan ilk talep
gelirse o kazanır.

QR'a isteğe bağlı parametre eklenir: `&r=<relay taban URL'i>` (URL-encode'lu;
`https://` zorunlu, yalnız testte loopback için `http://`). `r` yoksa relay
kullanılmaz. Telefonun sırası: `a` adresleri → mDNS → relay. `r` varken `a`
boş olabilir (`a=`; masaüstünün yerel ağ adresi yok) — telefon doğrudan
relay'e geçer.

### Relay API v1

| İstek | Anlam | Yanıt |
|---|---|---|
| `PUT /v1/box/{id}` gövde: ham bayt | Kutuya bir blob koy; 60 sn yaşar | `201`; kutu doluysa `409`; > 8 MiB `413`; hız sınırı `429`; bozuk `id` `404` |
| `GET /v1/box/{id}?wait=N` (`N` 0–25 sn) | Blob'u **al ve sil** (tek okuma, atomik); gelene kadar `N` sn bekle | `200` + gövde; hâlâ boşsa `204` |
| `GET /v1/health` | Canlılık | `200` |

- `id`: 43 karakter base64url (32 bayt), `^[A-Za-z0-9_-]{43}$`.
- `wait`: yoksa `0`; 25'ten büyükse 25'e indirilir; tam sayı değilse ya da
  negatifse `400`.
- Relay diskte hiçbir şey tutmaz (Redis, TTL 60 sn), erişim logu yok;
  yalnız toplam sayaçlar (kutu/bayt/gün). IP ve `id` loglanmaz.
- Boş gövdeli `PUT` geçerlidir.

### Kutu kimlikleri

```
box(name) = b64url( HMAC-SHA256(k, fields("portlight/pair/v1/relay", sid, name)) )
```

`name` ASCII: `claim`, `claim/response`, `reveal`, `reveal/response`,
`envelope`, `envelope/response`, `reject` (enroll uzantısı: `enroll`,
`enroll/response`, `enroll/result`, `enroll/result/response`, `close`). `k` olmadan kutular adreslenemez;
relay kutuları birbirine ya da bir oturuma bağlayamaz.

### Mesajlar

- **İstek kutusu** (`claim`, `reveal`, `envelope`, `reject`): gövde, doğrudan
  yoldaki HTTP isteğinin gövdesiyle birebir aynı JSON (`envelope` için boş).
  `reject`'in yanıt kutusu yoktur: telefon koyar ve bırakır (en iyi çaba).
- **Yanıt kutusu** (`…/response`): `uint16_be(HTTP durum kodu) ‖ yanıt gövdesi`
  — doğrudan yolda o isteğin alacağı durum ve gövde (zarf için age baytları).

```
Telefon                         Relay                          CLI
  PUT box(claim)  ─────────────►  │  ◄───────────── GET box(claim)?wait=25 (döngü)
                                  │                 isteği kendi handler'ından geçirir
  GET box(claim/response)?wait ◄──│◄─────────────── PUT box(claim/response)
  … reveal ve envelope aynı biçimde …
  PUT box(reject) (iptalde) ─────►│  ◄───────────── GET box(reject) (baştan beri, paralel)
```

- Her kutu tek kullanımlıktır (`409` = zaten dolu): relay yolunda talep
  tekrarlanmaz.
- Telefon `…/response` kutusunu `wait=25` ile, kendi süresi dolana kadar
  tekrar tekrar ister; `envelope/response` masaüstünün kararına kadar
  gecikebilir.
- CLI, `claim`'i el sıkışma süresi boyunca, `reveal`'i talepten sonra,
  `envelope`'u açıklamadan sonra dinler; `reject`'i baştan sona.
- Relay yolunda da her şey doğrudan yoldaki gibi MAC'li / age'le mühürlü;
  relay'in gördüğü: kutu kimlikleri, boyutlar, zamanlama, TCP düzeyinde IP.

### Telefon tarafı kuralları (pairing_client)

- Talep hangi yoldan başarılı olduysa (doğrudan / mDNS / relay) açıklama,
  zarf ve iptal de **aynı yoldan** gider.
- `claim/response` ve `reveal/response` relay'de ayrı ayrı en çok 30 sn
  beklenir (el sıkışmanın 60 sn tavanı içinde); zarf doğrudan yoldaki gibi
  70 sn.
- Telefonun `PUT`'u `409` alırsa: kutuyu yalnız QR sırrını bilen
  adresleyebildiği için bu **çakışma güvenlik uyarısıdır** (`conflict`).
- Relay `429`: 250 ms'den 4 sn'ye katlanan bekleme, `Retry-After` en çok
  4 sn'ye kadar dikkate alınır; `413`, diğer 4xx/3xx → `protocol`.
- Al-ve-sil nedeniyle HTTP yanıtı yolda kaybolan bir çerçeve kurtarılamaz;
  o adım süre dolunca biter.
- `r` doğrulaması: yalnız `https://` (loopback için `http://`), sorgu,
  fragment, kullanıcı bilgisi, nokta segmenti, ters bölü yok, en çok 512
  karakter. CLI relay taban URL'ine sorgu dizesi koymaz (Go `ParseURL` da
  reddeder).

## Kriptografik yardımcılar

Her HMAC/SHA-256 girdisi etiket + alanlardan oluşur; **her alanın önüne
4 baytlık big-endian uzunluğu** yazılır (etiket de dahil):

```
fields(label, f1, f2, …) = len(label) ‖ label ‖ len(f1) ‖ f1 ‖ …
```

| İşlev | Tanım |
|---|---|
| `Commitment(nonce_p)` | `SHA256(fields("portlight/pair/v1/commit", nonce_p))` |
| `ClaimMAC` | `HMAC-SHA256(k, fields("portlight/pair/v1/claim", sid, recipient, commitment))` |
| `RejectMAC` | `HMAC-SHA256(k, fields("portlight/pair/v1/reject", sid))` |
| `SAS` | `h = HMAC-SHA256(k, fields("portlight/pair/v1/sas", sid, recipient, nonce_c, nonce_p))`; `n = uint32_be(h[0:4]) mod 1 000 000`; `"%03d %03d"` |

`recipient`, telefonun bu eşleştirme için ürettiği geçici X25519 anahtarının
age biçimidir (`age1…`, bech32) ve UTF-8 baytları olarak girer.

## Akış

```
Telefon                                           CLI
  │ QR'ı okur; geçici age kimliği + nonce_p üretir
  │ POST /v1/pair/{sid}/claim ──────────────────────►  MAC'i doğrular (k ile)
  │   {recipient, commitment, mac}                     tek kullanımlık: ilk geçerli talep kazanır
  │ ◄──────────────────────────────────── 200 {cli_nonce}
  │ POST /v1/pair/{sid}/reveal ─────────────────────►  Commitment(nonce_p) eşleşmeli
  │   {phone_nonce}                                    SAS'ı gösterir, "aynı mı?" sorar
  │ ◄──────────────────────────────────── 202
  │ SAS'ı gösterir
  │ GET /v1/pair/{sid}/envelope ────────────────────►  (karar verilene kadar bekletir)
  │ ◄──────────────── 200 age dosyası (onaylandıysa)
  │ Kullanıcı telefonda da onaylarsa zarfı açar
```

- **Telefon, kullanıcı kendi ekranında kodu onaylamadan zarfı açmaz**
  (güvenlik kapısı). CLI de onaysız göndermez: iki taraflı onay.
- Zarf `age` v1 dosyasıdır, tek X25519 alıcı: `recipient`. Açıldığında
  içindeki JSON aşağıdaki payload'dır.
- Her istek gövdesi en çok 4 KiB, bilinmeyen JSON alanı reddedilir.
- **Telefondan iptal:** kullanıcı "kodlar farklı" der ya da akıştan çıkarsa
  telefon `POST /v1/pair/{sid}/reject {"mac": RejectMAC}` gönderir (en iyi
  çaba). Oturum talep edildikten sonraki her aşamada geçerlidir, CLI
  "cancelled on the phone; nothing was sent" ile biter → 204. MAC tutmazsa
  401 ve oturum etkilenmez. İstek ulaşmazsa CLI'ın kendi süresi oturumu
  bitirir.
- **Tekrarlanan talep:** aynı `recipient` + `commitment` ile gelen ikinci
  geçerli talep (telefon cevabı kaybedip başka adresten denediyse) aynı
  `cli_nonce` ile 200 alır; yanlışlıkla 409 güvenlik uyarısı üretmez.
- **Onaydan sonra da süre var:** masaüstü onayladıktan sonra zarf 60 sn
  içinde alınmazsa oturum sona erer (410).
- **Kapanış:** oturum bittiğinde CLI, telefonun sonucu (zarf / 403 / 410)
  görmesini en çok 5 sn bekler, sonra HTTP sunucusunu düzgünce kapatır —
  telefon "bağlanamadı" değil, gerçek sonucu görür.

### Durum kodları

| Kod | Anlam | Telefon ne yapar |
|---|---|---|
| 200 / 202 | Adım tamam | Devam |
| 400 | Bozuk istek; `reveal`'de taahhüt uymadıysa oturum **iptal** | Hata göster |
| 401 | Talep MAC'i tutmadı — oturum etkilenmez | Hata göster (QR'ı yeniden okut) |
| 403 | Masaüstünde kullanıcı "kodlar farklı" dedi | "Eşleşme reddedildi" |
| 404 | Böyle oturum yok | Hata göster |
| 409 | Oturumu başka biri talep etti / sıra dışı adım | **Güvenlik uyarısı** — ağda başka bir cihaz var |
| 410 | Oturum bitti (süre, iptal ya da zaten teslim edildi) | "Süre doldu, yeniden deneyin" |

## Neden bu kadar adım

- **`k` ile MAC:** QR'ı görmemiş biri oturumu talep edemez; yarışı
  kazansa bile 401 alır, telefonun talebi hâlâ geçer.
- **Taahhüt → nonce → açıklama:** QR sızmış ve saldırgan ağın ortasında
  olsa bile, SAS'ı kendi anahtarıyla çakıştırmak için telefonun nonce'unu
  önceden bilmesi gerekir; her iki yönde tek deneme hakkı, başarı şansı
  1/1 000 000.
- **Onaydan sonra mühürleme:** CLI zarfı yalnızca SAS'ın hesaplandığı
  `recipient`'e ve yalnızca onaydan sonra şifreler.

## Payload (JSON, v1)

```json
{
  "version": 1,
  "created_at": 1790360845,
  "hosts": [
    {"alias": "prod-1", "host_name": "10.0.0.1", "user": "ubuntu", "port": 2222,
     "key": "id_ed25519", "proxy_jump": "bastion", "group": "prod", "tags": []}
  ],
  "keys": [
    {"name": "id_ed25519", "algorithm": "ssh-ed25519",
     "public_key": "ssh-ed25519 AAAA…", "encrypted": false,
     "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n…"}
  ],
  "known_hosts": ["prod-1 ssh-ed25519 AAAA…"],
  "agents": [{"kind": "hermes"}, {"kind": "claude_code"}]
}
```

- `agents[].kind`: `hermes` (`~/.hermes` / `$HERMES_HOME`), `claude_code`
  (`~/.claude` / `$CLAUDE_CONFIG_DIR`), `openclaw` (`~/.openclaw`, eski adları
  `~/.clawdbot`, `~/.moltbot` / `$OPENCLAW_STATE_DIR`). Yalnız dizinin varlığına
  bakılır, içinde hiçbir dosya açılmaz; yol ve token gönderilmez. Token
  taşıma Faz 5'te, adaptör başına ayrı alanlarla gelecek — `~/.claude`'daki
  Anthropic oturum bilgisi hiçbir zaman taşınmaz.

- `hosts[].key`, `keys[].name`'e başvurur; masaüstündeki dosya yolu
  gönderilmez.
- `private_key` diskteki dosyanın aynısıdır. `encrypted: true` ise telefon
  içe aktarırken passphrase sorar (`KeysRepository` bunu zaten yapıyor).
- `proxy_jump` OpenSSH yazımıyla gelir (`user@host:port`, virgüllü zincir
  olabilir); uygulama şimdilik tek atlamayı destekliyor.
- `portlight export`, `private_key` alanı olmadan aynı JSON'u basar.
- `enroll` (isteğe bağlı): aşağıdaki "Enroll uzantısı". Yoksa masaüstü
  enroll sunmuyor (eski CLI ya da `--no-enroll`).

## Enroll uzantısı (v1 üstüne, 17 Ekim 2026)

Telefon kendi anahtarını üretir (StrongBox / Secure Enclave, P-256,
dışa aktarılamaz; donanım yoksa yazılımda, yine telefondan çıkmaz) ve
masaüstüne **yalnız açık anahtarını** gönderir; masaüstü kendi mevcut SSH
erişimiyle onu seçilen sunucuların `~/.ssh/authorized_keys` dosyasına ekler
ve sunucu başına sonucu bildirir. QR (`v=1`), el sıkışma, SAS ve zarf
değişmez; uzantı zarftan **sonra** aynı oturumda iki istek daha ekler.

### Uyumluluk

| Telefon | CLI | Sonuç |
|---|---|---|
| eski | yeni | Payload'daki `enroll` alanı bilinmeyen alan olarak yok sayılır. CLI zarftan sonra enroll süresince (5 dk) bekler; Ctrl+C ile ya da süre dolunca biter. `--no-enroll` v1'in birebir aynısıdır |
| yeni | eski | Payload'da `enroll` yok → telefon "telefon anahtarı ekle" seçeneğini göstermez, "CLI'ı güncelleyin" der |
| yeni | yeni | Aşağıdaki akış |

Payload `version` 1 kalır: alan eklemeli ve isteğe bağlıdır.

### Payload alanı

```json
"enroll": {"key": "<b64 32 bayt>", "only": false}
```

- `key` = `ek`: CLI'ın bu oturum için ürettiği 32 rastgele bayt. **Yalnız
  mühürlü zarfın içinde** gider, yani yalnız SAS'ı onaylanmış `recipient`'in
  sahibi (telefon) bilir. QR sırrı `k` sızmış olsa bile enroll isteği
  `ek` olmadan üretilemez: saldırgan kendi anahtarını sunuculara ekletemez.
- `only: true` — `portlight pair --enroll` (ya da `PORTLIGHT_ENROLL=1`):
  "anahtar kopyalama, telefona yeni anahtar ver" modu. Zarfta **hiç özel
  anahtar yoktur** (`keys: []`, `hosts[].key` boş); telefon doğrudan
  telefon anahtarı adımını açar.

### Türetilen değerler

```
K_req     = HKDF-SHA256(ikm = ek, salt = sid, info = "portlight/pair/v1/enroll/request", 32 bayt)
K_res     = HKDF-SHA256(ikm = ek, salt = sid, info = "portlight/pair/v1/enroll/result",  32 bayt)
CloseMAC  = HMAC-SHA256(ek, fields("portlight/pair/v1/enroll/close", sid))
seal(K, label, m) = {"nonce": b64(n), "box": b64(ChaCha20-Poly1305(K, n, m, aad = fields(label, sid)))}
                    n = 12 rastgele bayt
```

`label` istekte `portlight/pair/v1/enroll/request`, sonuçta
`portlight/pair/v1/enroll/result`. Her yönde tek mesaj ve ayrı anahtar
olduğu için nonce tekrarı yok; aad oturumu bağlar.

### Akış

```
Telefon                                              CLI
  │ … v1: claim, reveal, SAS, GET envelope (payload.enroll.key = ek) …
  │ kullanıcı host'ları seçer, telefonda anahtar üretilir
  │ POST /v1/pair/{sid}/enroll ────────────────────────►  açar (K_req), doğrular
  │   seal(K_req, {public_key, hosts})                    masaüstünde listeyi gösterir, "e/H?"
  │ ◄──────────────────────────────────────────── 202
  │ GET /v1/pair/{sid}/enroll/result ──────────────────►  onaylanırsa host'lara bağlanır,
  │                                                       authorized_keys'e ekler
  │ ◄──────────────── 200 seal(K_res, {results}) / 403 (masaüstünde reddedildi)
  │ başarılı host'ları yeni anahtara bağlar, ilkini dener
  │
  │ (vazgeçerse) POST /v1/pair/{sid}/close {"mac": CloseMAC} ──► 204, oturum biter
```

İstek gövdesi (açık hali):

```json
{"public_key": "ecdsa-sha2-nistp256 AAAA… portlight-phone",
 "hosts": [{"alias": "prod-1", "host_name": "10.0.0.1", "user": "ubuntu", "port": 22}]}
```

Sonuç (açık hali), istekteki sırayla:

```json
{"results": [
  {"alias": "prod-1", "status": "added",   "host_key": "ssh-ed25519 AAAA…"},
  {"alias": "web",    "status": "present", "host_key": "ecdsa-sha2-nistp256 AAAA…"},
  {"alias": "db",     "status": "failed",  "reason": "unknown_host_key"}
]}
```

| `status` | Anlam |
|---|---|
| `added` | Anahtar eklendi |
| `present` | Anahtar zaten vardı; dosyaya dokunulmadı |
| `failed` | Eklenmedi; `reason` neden |

| `reason` | Anlam |
|---|---|
| `not_known` | Masaüstü bu host'u tanımıyor (ne SSH config'te ne `known_hosts`'ta) — bağlanılmadı |
| `unknown_host_key` | Sunucunun anahtarı masaüstünün `known_hosts`'unda yok — **kabul edilmez** |
| `host_key_changed` | Sunucunun anahtarı `known_hosts`'takinden farklı |
| `auth_failed` | Masaüstünün anahtarları / agent'ı bu sunucuda geçmedi |
| `unreachable` | TCP/SSH bağlantısı kurulamadı |
| `proxy_jump` | ProxyJump zinciri (desteklenmiyor) ya da atlama host'u kullanılamadı |
| `write_failed` | `authorized_keys` okunamadı/yazılamadı (POSIX olmayan kabuk dahil) |
| `timeout` | Sunucu süresinde bitmedi |

`host_key`: CLI'ın bağlanırken gördüğü ve kendi `known_hosts`'uyla
doğruladığı sunucu anahtarı (`authorized_keys` biçiminde, yorum yok).
Telefon bunu yalnız o host:port için **hiç güvendiği anahtar yoksa**
kaydeder; farklı bir anahtara zaten güveniyorsa üzerine yazmaz (değişen
anahtar uyarısı aynen çalışır).

### Kurallar

- **Yalnız açık anahtar** gider. Telefonun özel anahtarı üretildiği yerden
  (StrongBox / Secure Enclave / platform kasası) hiç çıkmaz.
- `public_key`: tek satır, seçeneksiz (`EnrollKey` ile aynı doğrulama), CLI
  satırı yeniden kodlar; sunucuya yalnız `<tür> <base64> portlight-mobile`
  yazılır. 1–64 host, istek gövdesi en çok 32 KiB, bilinmeyen alan reddedilir.
- **CLI yalnız zaten tanıdığı yere bağlanır:** istekteki host ya SSH
  config/PuTTY'deki bir alias'tır (`host_name` ve `port` uymalı; bağlanırken
  config'in `HostName`/`Port`/`IdentityFile`/`ProxyJump`'ı kullanılır) ya da
  `host_name:port` masaüstünün `known_hosts`'unda vardır (hash'li satırlar
  dahil). Değilse `not_known`, hiç bağlanılmaz. `user` istekten gelir ve
  onay listesinde görünür.
- **Masaüstü onayı:** CLI host listesini (`user@host:port`) ve anahtarın
  parmak izini gösterip "e/H" sorar; onaydan önce hiçbir sunucuya
  bağlanılmaz. Karar süresi 60 sn; süre ya da "hayır" → `403`.
- **Bağlantı:** `golang.org/x/crypto/ssh`; kimlik doğrulama ssh-agent
  (`SSH_AUTH_SOCK`, Windows'ta OpenSSH agent pipe'ı), host'un
  `IdentityFile`'ı ve varsayılan anahtarlar (`id_ed25519`, `id_ecdsa`,
  `id_rsa`, PuTTY `.ppk` dönüşümü dahil). Passphrase'li anahtar için onaydan
  sonra bir kez sorulur (boş = atla). Sunucu anahtarı `~/.ssh/known_hosts`
  ile doğrulanır; **bilinmeyen anahtar asla otomatik kabul edilmez.**
  ProxyJump tek atlama desteklenir (atlama host'u da aynı kurallarla).
- **Uzak komutlar** (anahtar satırı komut satırına girmez, stdin'den gider):
  okuma `sh -c 'test ! -e .ssh/authorized_keys || cat .ssh/authorized_keys'`;
  anahtar yoksa ekleme `sh -c 'umask 077 && mkdir -p .ssh && cat >> .ssh/authorized_keys'`.
  Anahtar blob'u karşılaştırılır (seçenekli satırdaki aynı anahtar da
  "var" sayılır). Dosya satır sonuyla bitmiyorsa önce `\n` yazılır.
- **CLI yerelde hiçbir şey yazmaz.** Masaüstündeki tek iz ekrandaki çıktıdır.
- Süreler: zarf teslim edildikten sonra enroll isteği için **5 dk**; istek
  gelince masaüstü kararı 60 sn; dağıtım en çok 180 sn (host başına 15 sn
  bağlantı + 15 sn komut, aynı anda 4 host). Telefon `enroll/result`'u en çok
  60 + 180 + 10 sn bekler.
- Oturum yine tek kullanımlık: kabul edilen ikinci `enroll` → `409`;
  sonuç teslim edilince, `close` gelince, `reject` gelince ya da süre
  dolunca oturum biter.

### Durum kodları (uzantı)

| İstek | Kod | Anlam |
|---|---|---|
| `enroll` | 202 | Kabul; masaüstü soruyor |
| `enroll` | 400 | Açıldı ama içerik geçersiz (anahtar, host sayısı) — oturum sürer |
| `enroll` | 401 | `K_req` ile açılmadı (`ek` bilinmiyor) — oturum etkilenmez |
| `enroll` | 404 / 409 / 410 | Oturum yok / zaten istendi ya da enroll sunulmadı / bitti |
| `enroll/result` | 200 | Sonuç |
| `enroll/result` | 403 | Masaüstünde reddedildi ya da karar süresi doldu |
| `enroll/result` | 409 / 410 | İstek yok / oturum bitti |
| `close` | 204 / 401 / 409 / 410 | Kapandı / MAC tutmadı / dağıtım sürüyor / zaten bitti |

### Relay

Yeni kutu adları: `enroll`, `enroll/response`, `enroll/result`,
`enroll/result/response`, `close` (yanıt kutusu yok, `reject` gibi). CLI
`enroll`'ü ve `close`'u zarf teslim edildikten sonra, `enroll/result`'u
istek kabul edildikten sonra dinler. Relay'in gördüğü yine yalnız kutu
kimlikleri, boyutlar ve zamanlama: istek ve sonuç `ek`'ten türetilen
anahtarlarla mühürlü, `ek` zarfın içinde.

## Açık

- Relay yolu (Faz 2c): CLI tarafı uygulandı (`cli/internal/relay`,
  `ServeRelay`, `portlight pair --relay` / `PORTLIGHT_RELAY`; geliştirme için
  `go run ./cmd/devrelay`). Herkese açık relay adresi henüz belli değil;
  varsayılan: relay yok.
- Windows'ta ağ "Genel" profildeyse güvenlik duvarı gelen bağlantıyı
  engeller; CLI kullanıcıya "İzin ver" demesini söylüyor. mDNS gidiş-dönüşü
  bu yüzden geliştirme makinesinde doğrulanamadı (test atlanıyor).
- Dart tarafında age: `dartage` paketi var ama çok az kullanılıyor
  (Eylül 2026'da 123 indirme); X25519 alıcı + STREAM'i
  `package:cryptography` ile yazıp Go'nun ürettiği vektörlerle test etmek
  daha güvenli seçenek. Karar Faz 2b'de.
