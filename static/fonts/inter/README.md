# Inter

Unmodified Inter 4.1 variable web fonts, self-hosted for all vault and
administration UI. The regular and italic files cover weights 100–900.

Upstream: https://github.com/rsms/inter/tree/v4.1/docs/font-files

Files:

- `InterVariable.woff2`
- `InterVariable-Italic.woff2`
- `LICENSE.txt` — upstream SIL Open Font License 1.1 and copyright notice.

`static/css/tokens.css` registers both faces and makes Inter the first family
in the shared font token. Both base templates preload the regular face;
italic loads only when needed. No external font requests or font CDN are used.
