# Durum Günlüğü

> En üstteki kayıt en güncelidir. Her çalışma sonrası buraya kısa bir not düşülür.

---

## 2026-08-21 — Proje oluşturuldu, test edildi, CI eklendi

- Konu: Bir domain'in subdomain'lerinde dangling-CNAME takeover riskini tarayan CLI aracı. `DNS-Security-Auditor`'daki gibi sıfırdan yazılmış bir raw UDP DNS istemcisi (CNAME + A kaydı) kullanıyor, HTTP tarafı için stdlib `urllib`. Akış: CNAME çöz → hedef bilinen bir bulut servisine mi işaret ediyor (GitHub Pages/Heroku/S3/Shopify/Fastly/Surge.sh/Unbounce/Tumblr) → hedef gerçekten çözülüyor mu (çözülmüyorsa dangling CNAME, HIGH) → çözülüyorsa HTTP'de o servisin bilinen "unclaimed" fingerprint'i var mı (varsa HIGH, site erişilemiyorsa MEDIUM, yoksa temiz).
- **Önemli kapsam/etik kararı**: Bu araç `DNS-Security-Auditor`'dan farklı olarak salt bir DNS kaydı sorgusu değil, bir hedefin subdomain'lerini ENUMERATE eden bir recon tekniği — bu yüzden gerçek bir üçüncü taraf domain'ine karşı "örnek" çalıştırma yapılmadı (Port-Scan-Reporter'ın scanme.nmap.org'u gibi bunun için özel olarak sunulmuş bir domain yok). Bunun yerine `Port-Scan-Reporter`'ın `demo_local.py` felsefesiyle birebir aynı yaklaşım: tamamen yerel, sahte bir DNS sunucusu + sahte bir HTTP sunucusu (her ikisi de gerçek soket/thread, 127.0.0.1) kurup gerçek `check_subdomain()` fonksiyonunu 4 senaryoya karşı çalıştırdı — hiçbir gerçek internet erişimi veya üçüncü taraf hedef olmadan.
- `demo_local.py` geliştirilirken gerçek bir Windows'a özgü hata yakalandı: sunucu thread'i `recvfrom()` içinde bloke olmuşken ana thread soketi kapatınca `OSError [WinError 10038]` fırlatıyordu. Kısa bir recv timeout (0.2s) ile thread'in kendi kendine `_stop` bayrağını kontrol edip çıkmasını sağlayarak, socket.close() çağrılmadan ÖNCE thread'in gerçekten bitmiş olması garanti edildi — düzeltme sonrası hatasız, temiz bir çalıştırma doğrulandı.
- Dosya: `subdomain_takeover_scanner.py`, `demo_local.py`, `tests/test_subdomain_takeover_scanner.py` (25 test), `pyproject.toml`, `.github/workflows/ci.yml`.
- Test stratejisi: DNS wire-format fonksiyonları gerçek bir yerel sahte UDP DNS sunucusuna karşı gerçek socket round-trip ile test edildi; `check_subdomain`'in orkestrasyon mantığı I/O sınırında (`query`, `fetch_body`) mock'landı.
- Baştan itibaren eklenenler: `--format json`, `--fail-on {none,medium,high}`.
- Durum: ✅ 25/25 test gerçekten çalıştırılıp geçti, `ruff check .` temiz. `demo_local.py` gerçekten çalıştırıldı: 4 senaryodan 2'si doğru şekilde işaretlendi (dangling CNAME + fingerprint eşleşmesi), diğer 2'si (düzgün claim edilmiş + CNAME yok) doğru şekilde işaretlenmedi. `sample_report.md` bu gerçek (yerel) çalıştırmadan üretildi. Henüz push edilmedi (repo local).

**Sıradaki iş:** GitHub'da `Subdomain-Takeover-Scanner` adıyla repo aç, git init + push.
