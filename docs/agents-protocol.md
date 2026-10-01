# Ajan panelleri — sunucu ↔ telefon sözleşmesi (v1)

**Durum:** taslak, 26 Eylül 2026. İlk adaptör: Claude Code.
**Kapsam:** telefonun, sunucuda çalışan bir AI ajanının onay isteklerini
görmesi ve yanıtlaması, olay akışı ve tmux oturumlarına bağlanma.
Push bildirimi (FCM/APNs + relay) **yok** — telefon uygulama açıkken SSH
üstünden sorar. Hermes ve OpenClaw adaptörleri gerçek API'leri
doğrulanınca aynı arayüze eklenecek.

## İlke

- **Ağ yüzeyi yok.** Sunucuda dinleyen port, daemon ya da relay yok.
  Telefon, zaten güvendiği SSH bağlantısıyla (`sessions_repository.runCommand`)
  sabit komutlar çalıştırır. Kimlik doğrulama SSH'nin kendisidir.
- **Varsayılan asla "izin ver" değildir.** Karar gelmezse, bozuk gelirse ya
  da bir şey ters giderse hook `ask` döner: Claude Code kendi terminal
  sorusunu sorar, yani durum Portlight hiç kurulmamış gibidir.
- **Onay telefonda uygulama PIN'i ister**, onay anında girilir
  (güvenlik kapısı). Reddetmek tek dokunuştur.
- Telefonun çalıştırdığı her komut sabit bir şablondur; değişken kısımlar
  (id, karar) katı regex'le doğrulanır, kabuğa ham metin gitmez.

## Sunucu tarafı: `portlight` CLI

Aynı Go ikilisi (masaüstünde `pair` yapan) sunucuda da çalışır.

| Komut | Ne yapar |
|---|---|
| `portlight agent install claude-code [--wait 120s]` | `~/.claude/settings.json`'a hook girdisini **birleştirerek** ekler (önce `settings.json.portlight-bak` yedeği; başka hook'lara dokunmaz), `install.json` yazar |
| `portlight agent uninstall claude-code` | Yalnız kendi eklediği girdiyi siler |
| `portlight agent hook claude-code` | Hook'un kendisi: stdin'den olay JSON'u okur, stdout'a karar yazar |
| `portlight agent status --json` | Kurulu adaptörler, sürüm, bekleyen sayısı |
| `portlight agent pending --json` | Bekleyen onay istekleri |
| `portlight agent decide <id> allow\|deny [--reason TEXT]` | Kararı yazar |
| `portlight agent events --json [--limit N]` | Son olaylar (en yeni sonda) |

## Dosya düzeni

```
~/.portlight/                       0700
  agents/claude-code/               0700
    install.json                    0600  {"v":1,"binary":"/abs/path/portlight","version":"…","wait_seconds":120,"installed_at":…}
    pending/<id>.json               0600  bekleyen istek
    decisions/<id>.json             0600  telefonun kararı
    events.jsonl                    0600  olay günlüğü, son 1000 satır
```

- `<id>`: 16 rastgele bayt, küçük harf hex — `^[0-9a-f]{32}$`.
- Tüm yazmalar atomik: aynı dizinde geçici dosya → `rename`.

### `pending/<id>.json`

```json
{
  "v": 1, "id": "…", "agent": "claude_code",
  "created_at": 1790400000, "expires_at": 1790400120,
  "session_id": "…", "cwd": "/srv/app",
  "tool": "Bash",
  "summary": "npm ci && rm -rf ./build",
  "input": { "command": "npm ci && rm -rf ./build", "description": "…" }
}
```

`summary`: araç girdisinin tek satırlık, en çok 200 karakterlik özeti
(Bash için komutun kendisi; dosya araçları için yol). `input`: araç girdisi,
en çok 16 KiB (aşarsa kırpılır ve `"input_truncated": true`).

### `decisions/<id>.json`

```json
{ "v": 1, "id": "…", "decision": "allow", "reason": "Onaylandı: Portlight", "decided_at": 1790400042 }
```

`decision` yalnız `allow` ya da `deny`. İlgili `pending/<id>.json` yoksa
ya da süresi geçtiyse `portlight agent decide` hata verir (çıkış kodu 3)
ve karar yazılmaz.

### `events.jsonl`

Satır başına bir JSON: `{"v":1,"ts":…,"type":"request|allow|deny|expired|notification|stop","id":"…","session_id":"…","summary":"…"}`.
`request/allow/deny/expired` onay isteklerinin yaşamı; `notification` ve
`stop` Claude Code'un bildirim ve oturum bitiş hook'larından. En çok 1000
satır tutulur (eskisi atılır).

## Hook akışı (Claude Code)

1. Claude Code, kullanıcıdan izin isteyeceği bir araç çağrısında
   `PermissionRequest` hook'unu çağırır (matcher `*`). `PreToolUse` değil:
   o her araç çağrısında tetiklenir ve izin kurallarının bir kopyasını
   gerektirirdi; `PermissionRequest` yalnız Claude Code gerçekten soracakken
   gelir. `-p`, `dontAsk` ve `bypassPermissions` modlarında hiç tetiklenmez
   (26 Eylül 2026 belgelerine göre; ayrıntı `cli/internal/agent/hook.go`).
2. Hook `pending/<id>.json` yazar, `events.jsonl`'a `request` ekler.
3. `decisions/<id>.json` gelene kadar 500 ms aralıkla bakar, en çok
   `wait_seconds` (varsayılan 120; hook'un Claude Code tarafındaki `timeout`
   değeri bundan 10 sn uzun ayarlanır).
4. Karar `allow` → Claude Code'a izin; `deny` → ret (gerekçesiyle).
   Süre dolarsa / karar okunamazsa → `ask` + `expired` olayı.
   `PermissionRequest`'te "ask" davranışı yoktur: hook hiçbir şey yazmadan
   0 koduyla çıkar, Claude Code kendi sorusunu sorar. (Çıkış kodu 2 bu
   olayda dikkate alınmaz; kullanılmaz.)
5. Her durumda `pending` ve `decisions` dosyalarını siler.

Onay gerektirmeyen olaylar (bildirim, oturum sonu) yalnız `events.jsonl`'a
yazılır; hook hemen döner ve Claude Code'u hiç bekletmez.

## Telefon tarafı

1. **Keşif:** `cat ~/.portlight/agents/claude-code/install.json` — yoksa
   "kurulu değil" (+ kurulum talimatı). `binary` mutlak yol ve
   `^/[A-Za-z0-9._/+-]+$` olmalı.
2. Sonraki her komut `<binary> agent … --json` biçiminde, sabit argümanlarla.
3. Bekleyen istekler ekranı açıkken birkaç saniyede bir yoklanır.
4. **Onay:** isteğin tam içeriği (araç, komut, çalışma dizini) gösterilir,
   uygulama PIN'i o anda istenir, sonra `decide <id> allow`. **Ret:**
   `decide <id> deny`.
5. **tmux:** `tmux ls -F '#{session_name}|#{session_created}|#{session_attached}'`
   (ayırıcı `|`: tmux 3.x `-F` çıktısında sekmeyi `_` yapıyor)
   ile oturumlar listelenir; bağlanma, terminal sekmesinde
   `tmux attach -t <ad>` (ad `^[A-Za-z0-9._-]{1,64}$`).

## Açık

- Push bildirimi (Faz 5, Firebase/APNs + relay'de uçtan uca şifreli zarf).
- Hermes (`/api/status`, oturumlar, cron, skills) ve OpenClaw (gateway API)
  adaptörleri — gerçek kurulumda doğrulanmadan yazılmayacak.
