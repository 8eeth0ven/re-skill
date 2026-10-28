# Platform Branch Maintenance

## Reading and corpus lookup

> Usage: the entry point is the branch router in [`../SKILL.md`](../SKILL.md); open 1-2 files by name per task, reading the whole library is forbidden. The entry point for the local corpus (Jinghua vols 1-24 CHM, 18,915 articles) is `../data/精华全量索引.md`; after locating an article, run `7z x pediyNN.chm "pediyNN/<tid>.html" "pediyNN/<tid>" -o<dir>` to extract the body + images (gb18030 encoding; images can be viewed directly with Read).
> Historical source-inventory note (retained for provenance; verify current acquisition status separately): the knowledge base's ten top-level categories (chm.htm tree, 1702 nodes) + local Jinghua vols 1-24 full text + 2025 Jinghua 651-article index (Jinghua vol 26 not yet officially released)

## Maintenance conventions

- New content goes into the area md, then a row is added to [`INDEX.md`](INDEX.md); the index stores routes only
- Body text keeps no external links / source attributions / personal names / verification dates, only approaches and hard-won knowledge; for corpus sources use the data/ indexes
- Images: extract the local original and view with Read, then convert to ASCII/text and mark "local original parsed"; purely online posts are marked "restored as text"
- When in conflict with `~/.zcode/rules`, rules win
