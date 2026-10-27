# Security policy

This repository is the source of a personal portfolio site. It is a security portfolio, so it is
held to the standard it describes. The authoritative, machine-readable contact is
[`/.well-known/security.txt`](.well-known/security.txt); the human-readable policy is served at `/security/`.

## Reporting a vulnerability

Email the address in `security.txt` with a subject starting with `[security]`. Include the URL,
steps to reproduce and your view of the impact. Encrypt to the PGP key referenced from
`security.txt` once it is published. Do not open a public issue for anything exploitable.

## Scope

In scope: the HTML, CSS, JavaScript, headers and `.well-known` files served from the site's origin,
and the contact form including honeypot bypass or content injection.

Out of scope: the hosting platform (Netlify) and its infrastructure, denial of service and
volumetric testing, social engineering, physical attacks, and reports that headers are missing
on local or third-party mirrors.

## Response

- Acknowledgement within 7 days.
- Fix or written explanation within 30 days for confirmed issues.
- Credit on the site's policy page, if wanted, once closed.

## Safe harbour

Good-faith research within the scope above that avoids privacy violations, data destruction and
service disruption will not lead to legal action from the site owner. When in doubt, ask first.

## Supply chain

The site has no dependencies at build or run time. The only external tool in the pipeline is
`openssl`, used by `scripts/build.sh` to compute hashes. Fonts are vendored in `fonts/`.
