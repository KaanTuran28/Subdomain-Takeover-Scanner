# Subdomain Takeover Scan — demo.test

- **Subdomains checked:** 4
- **Findings:** 2 HIGH, 0 MEDIUM

| Severity | Subdomain | Check | Reason |
|---|---|---|---|
| HIGH | blog.demo.test | dangling_cname | CNAME points to "old-project.github.io" (GitHub Pages), which does not resolve at all — a classic dangling-CNAME takeover setup. |
| HIGH | shop.demo.test | subdomain_takeover_fingerprint | CNAME points to Shopify ("tenant.myshopify.com") and the site returns its published "unclaimed resource" fingerprint ("Sorry, this shop is currently unavailable."). |
