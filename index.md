---
layout: page
title: "Flare-On Write-ups"
---

# The Flare-On Challenge Write-ups

Welcome. This site documents my solutions to the **[Flare-On](https://flare-on.com/)** challenge series —
an annual reverse engineering competition run by Mandiant's FLARE team, widely regarded as one of the
most rigorous RE challenges available.

Each write-up follows the same structured format:

- **Executive Summary** — what the challenge is and what the flag is
- **Initial Triage** — file type identification, entropy analysis, packer detection
- **Static Analysis** — disassembly and decompilation walk-through (IDA Free, Ghidra)
- **Dynamic Analysis** — debugger-assisted execution tracing (x32dbg, x64dbg)
- **Flag Extraction** — the exact steps that produced the solution

---

## About

I'm a Computer Science graduate working toward a career in malware analysis and reverse engineering.
These write-ups serve both as personal documentation and as a public record of my progress through
the Flare-On series. All analysis was performed inside an isolated FlareVM environment.

My other work and notes live on **[GitHub](https://github.com/alexandrubunea)**.

---

## Write-ups

{% assign posts_by_year = site.posts | group_by_exp: "post", "post.date | date: '%Y'" %}
{% for year_group in posts_by_year %}
### Flare-On {{ year_group.name }}

{% for post in year_group.items %}
- [{{ post.title }}]({{ post.url | relative_url }}) <span style="color: gray; font-size: 0.85em;">— {{ post.date | date: "%B %-d, %Y" }}</span>
{% endfor %}

{% endfor %}