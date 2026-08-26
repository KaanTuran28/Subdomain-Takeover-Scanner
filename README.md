# Subdomain Takeover Scanner

![CI](https://github.com/KaanTuran28/Subdomain-Takeover-Scanner/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

<p align="center"><b><a href="#english">English</a></b> · <b><a href="#türkçe">Türkçe</a></b></p>

---

## English

> ⚠️ **Authorized use only.** This enumerates subdomains of, and sends real DNS/HTTP requests to, the domain you name. Only run it against a domain you own or are explicitly authorized to test (e.g. a bug bounty program's in-scope assets).

Scans a domain's subdomains for **dangling-CNAME takeover risk** — a CNAME pointing at a cloud resource (GitHub Pages, Heroku, S3, Shopify, ...) that was deprovisioned but never removed from DNS, letting anyone who claims that resource name serve content on your subdomain.

### Overview

Built on a small, from-scratch DNS client (raw UDP, RFC 1035 wire format — same approach as this portfolio's [`DNS-Security-Auditor`](../DNS-Security-Auditor)), plus a plain `urllib` HTTP fetch. No `dnspython`, no `requests`, no other resolver/HTTP dependency.

For each candidate subdomain:
1. Resolve its **CNAME**. No CNAME → not a candidate, skip.
2. Check whether the CNAME target matches a known cloud-service pattern (GitHub Pages, Heroku, AWS S3, Shopify, Fastly, Surge.sh, Unbounce, Tumblr). Not a match → skip.
3. Check whether the CNAME **target itself still resolves**. If not → **dangling CNAME**, the classic takeover setup — HIGH, no further check needed.
4. If it resolves, fetch the subdomain over HTTP and check for that service's published **"unclaimed resource" fingerprint** (the same public fingerprint list bug-bounty tooling like `can-i-take-over-xyz` documents). Fingerprint present → **takeover confirmed** — HIGH. Site unreachable → **MEDIUM** (inconclusive, needs a manual look). Fingerprint absent → properly claimed, no finding.

### Installation

Requires Python 3.9+. No external dependencies.

```bash
git clone <this-repo>
cd Subdomain-Takeover-Scanner
pip install -e .
```

This installs a `subdomain-takeover-scanner` command. You can also run the script directly with `python subdomain_takeover_scanner.py` without installing.

### Usage

```bash
subdomain-takeover-scanner --domain example.com --output report.md
subdomain-takeover-scanner --domain example.com --wordlist my_subdomains.txt --format json --output report.json
```

| Flag | Default | Description |
|---|---|---|
| `--domain` | *(required)* | Domain to scan |
| `--wordlist` | *(built-in ~16 names)* | Path to a file of subdomain prefixes, one per line |
| `--resolver` | `8.8.8.8` | DNS resolver IP to query |
| `--timeout` | `5.0` | Per-query/request timeout in seconds |
| `--output` | `sample_report.md` | Path to write the report |
| `--format` | `markdown` | `markdown` or `json` |
| `--fail-on` | `none` | `none`, `medium`, or `high` — exit code `1` if a finding at/above this severity exists |

### Try it yourself (no network or target required)

```bash
python demo_local.py
```

Spins up throwaway local DNS + HTTP servers on `127.0.0.1` and runs the real scan pipeline against four synthetic scenarios — a fully reproducible demo that touches no third-party infrastructure. See **Example Output** below.

### CI Integration

Run this on a schedule against your own domain's known subdomains:

```bash
subdomain-takeover-scanner --domain example.com --wordlist known_subdomains.txt --fail-on high
```

```yaml
# GitHub Actions step (e.g. on a schedule trigger)
- name: Check for dangling subdomain CNAMEs
  run: subdomain-takeover-scanner --domain example.com --wordlist known_subdomains.txt --fail-on high
```

### Example Output

See [`sample_report.md`](./sample_report.md) — real output from `demo_local.py`'s four fully-local scenarios: a dangling CNAME (`blog.demo.test` → an unresolvable GitHub Pages target), a confirmed-takeover fingerprint match (`shop.demo.test` → a Shopify page returning the "shop unavailable" fingerprint), a properly claimed resource (`www.demo.test`, no finding), and a subdomain with no CNAME at all (`mail.demo.test`, no finding). **2 of 4 flagged.**

This project's canonical example is local rather than a live domain scan on purpose — see the docstring in `demo_local.py` for why (subdomain enumeration against a real target is a recon technique, unlike a plain DNS-record lookup, and there's no public "please enumerate me" equivalent of `Port-Scan-Reporter`'s `scanme.nmap.org`).

### Limitations

Only follows a single CNAME hop (not a full CNAME chain), only knows a small, static set of service fingerprints, and the default wordlist is a short, common-name list rather than a large brute-force dictionary. A "no finding" result means none of these specific heuristics fired — not a certification that no subdomain is takeover-vulnerable.

### Testing

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

The DNS wire-format functions get a real UDP socket round-trip test against a local fake server (no internet needed); `check_subdomain`'s orchestration and the HTTP fetch are exercised via monkeypatching at the I/O boundary.

### Project Structure

```
Subdomain-Takeover-Scanner/
├── subdomain_takeover_scanner.py
├── demo_local.py
├── pyproject.toml
├── sample_report.md
├── tests/
│   └── test_subdomain_takeover_scanner.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── DURUM.md
```

### License

MIT — see [LICENSE](./LICENSE).

---

## Türkçe

> ⚠️ **Sadece yetkili kullanım.** Bu araç, belirttiğiniz domain'in alt alan adlarını (subdomain) numaralandırır ve bu domain'e gerçek DNS/HTTP istekleri gönderir. Sadece sahibi olduğunuz veya test etmek için açıkça yetkilendirildiğiniz bir domain'e karşı çalıştırın (örn. bir bug bounty programının kapsam dahilindeki varlıkları).

Bir domain'in alt alan adlarını **dangling-CNAME devralma (takeover) riskine** karşı tarar — bir cloud kaynağına (GitHub Pages, Heroku, S3, Shopify, ...) işaret eden ancak devre dışı bırakıldığı halde DNS'ten hiç kaldırılmamış bir CNAME, o kaynak adını talep eden herkesin sizin alt alan adınızda içerik sunmasına izin verir.

### Genel Bakış

Küçük, sıfırdan yazılmış bir DNS istemcisi (ham UDP, RFC 1035 wire format — bu portföydeki [`DNS-Security-Auditor`](../DNS-Security-Auditor) ile aynı yaklaşım) ve düz bir `urllib` HTTP isteği üzerine inşa edilmiştir. `dnspython` yok, `requests` yok, başka bir resolver/HTTP bağımlılığı yok.

Her aday alt alan adı için:
1. **CNAME**'ini çözümle. CNAME yoksa → aday değil, atla.
2. CNAME hedefinin bilinen bir cloud servis desenine (GitHub Pages, Heroku, AWS S3, Shopify, Fastly, Surge.sh, Unbounce, Tumblr) uyup uymadığını kontrol et. Uymuyorsa → atla.
3. CNAME **hedefinin kendisinin hâlâ çözümlenip çözümlenmediğini** kontrol et. Çözümlenmiyorsa → **dangling CNAME**, klasik devralma kurulumu — HIGH, başka kontrol gerekmez.
4. Çözümleniyorsa, alt alan adını HTTP üzerinden getir ve o servisin yayımladığı **"talep edilmemiş kaynak" parmak izini (fingerprint)** kontrol et (bug-bounty araçlarının, örneğin `can-i-take-over-xyz`'nin belgelediği aynı public fingerprint listesi). Fingerprint mevcutsa → **devralma doğrulandı** — HIGH. Site erişilemezse → **MEDIUM** (kesin değil, manuel bakış gerekir). Fingerprint yoksa → düzgün şekilde talep edilmiş, bulgu yok.

### Kurulum

Python 3.9+ gerektirir. Harici bağımlılık yoktur.

```bash
git clone <this-repo>
cd Subdomain-Takeover-Scanner
pip install -e .
```

Bu, bir `subdomain-takeover-scanner` komutu kurar. Kurulum yapmadan doğrudan `python subdomain_takeover_scanner.py` ile de çalıştırabilirsiniz.

### Kullanım

```bash
subdomain-takeover-scanner --domain example.com --output report.md
subdomain-takeover-scanner --domain example.com --wordlist my_subdomains.txt --format json --output report.json
```

| Flag | Varsayılan | Açıklama |
|---|---|---|
| `--domain` | *(zorunlu)* | Taranacak domain |
| `--wordlist` | *(dahili ~16 isim)* | Her satırda bir tane olmak üzere alt alan adı ön eklerinin bulunduğu dosyanın yolu |
| `--resolver` | `8.8.8.8` | Sorgulanacak DNS resolver IP'si |
| `--timeout` | `5.0` | Sorgu/istek başına zaman aşımı (saniye) |
| `--output` | `sample_report.md` | Raporun yazılacağı dosya yolu |
| `--format` | `markdown` | `markdown` veya `json` |
| `--fail-on` | `none` | `none`, `medium` veya `high` — bu önem seviyesinde veya üzerinde bir bulgu varsa çıkış kodu `1` |

### Kendiniz deneyin (ağ veya hedef gerekmez)

```bash
python demo_local.py
```

`127.0.0.1` üzerinde geçici, yerel DNS + HTTP sunucuları başlatır ve gerçek tarama pipeline'ını dört sentetik senaryoya karşı çalıştırır — üçüncü taraf altyapısına hiç dokunmayan, tamamen tekrarlanabilir bir demo. Aşağıdaki **Örnek Çıktı** bölümüne bakın.

### CI Entegrasyonu

Bunu kendi domain'inizin bilinen alt alan adlarına karşı zamanlanmış olarak çalıştırın:

```bash
subdomain-takeover-scanner --domain example.com --wordlist known_subdomains.txt --fail-on high
```

```yaml
# GitHub Actions adımı (örn. bir zamanlama tetikleyicisinde)
- name: Check for dangling subdomain CNAMEs
  run: subdomain-takeover-scanner --domain example.com --wordlist known_subdomains.txt --fail-on high
```

### Örnek Çıktı

Bkz. [`sample_report.md`](./sample_report.md) — `demo_local.py`'nin dört tamamen yerel senaryosundan alınan gerçek çıktı: bir dangling CNAME (`blog.demo.test` → çözümlenemeyen bir GitHub Pages hedefi), doğrulanmış bir devralma fingerprint eşleşmesi (`shop.demo.test` → "shop unavailable" fingerprint'ini döndüren bir Shopify sayfası), düzgün şekilde talep edilmiş bir kaynak (`www.demo.test`, bulgu yok) ve hiç CNAME'i olmayan bir alt alan adı (`mail.demo.test`, bulgu yok). **4 üzerinden 2'si işaretlendi.**

Bu projenin kanonik örneği kasıtlı olarak canlı bir domain taraması yerine yereldir — nedenini `demo_local.py`'deki docstring'de görebilirsiniz (gerçek bir hedefe karşı alt alan adı numaralandırması, düz bir DNS kaydı sorgusunun aksine bir recon tekniğidir ve `Port-Scan-Reporter`'ın `scanme.nmap.org`'una benzer, public "beni numaralandır" muadili yoktur).

### Sınırlamalar

Sadece tek bir CNAME atlamasını takip eder (tam bir CNAME zincirini değil), sadece küçük, statik bir servis fingerprint kümesini bilir ve varsayılan wordlist büyük bir kaba kuvvet sözlüğü yerine kısa, yaygın isimlerden oluşan bir listedir. "Bulgu yok" sonucu, bu spesifik sezgisellerin hiçbirinin tetiklenmediği anlamına gelir — hiçbir alt alan adının devralmaya karşı savunmasız olmadığının bir sertifikası değildir.

### Test

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

DNS wire-format fonksiyonları, yerel bir sahte sunucuya karşı gerçek bir UDP socket round-trip testinden geçer (internet gerekmez); `check_subdomain`'in orkestrasyonu ve HTTP isteği, I/O sınırında monkeypatching ile test edilir.

### Proje Yapısı

```
Subdomain-Takeover-Scanner/
├── subdomain_takeover_scanner.py
├── demo_local.py
├── pyproject.toml
├── sample_report.md
├── tests/
│   └── test_subdomain_takeover_scanner.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── DURUM.md
```

### Lisans

MIT — bkz. [LICENSE](./LICENSE).
