# OWASP CRS - Movable Type Rule Exclusions Plugin
[![Integration tests](https://github.com/futsure0/movabletype-rule-exclusions-plugin/actions/workflows/integration.yml/badge.svg?branch=main)](https://github.com/futsure0/movabletype-rule-exclusions-plugin/actions/workflows/integration.yml?query=branch%3Amain)

## Description

This plugin contains rule exclusions for the administration screens of
[Movable Type](https://movabletype.org/), so that users can save entries,
pages and templates and upload assets without being blocked by OWASP CRS
(CRS).

The exclusions are deliberately narrow:

* only `POST` requests to the administration script (`mt.cgi`, in any
  directory),
* only when the Movable Type login cookie (`mt_user`) is present,
* only for these fields and rules:

| What | Field | Rules excluded |
|---|---|---|
| Body of entries, pages and templates | `text` | XSS (tag `attack-xss`), 934100 |
| Extended body of entries and pages | `text_more` | XSS (tag `attack-xss`), 934100 |
| Asset upload (`multipart/form-data`) | — | 200004 |

Authors routinely put script tags (maps, embeds), event handlers, HTML
comments and Movable Type template tags such as
`<$mt:SetVar name="a" value="1"$>` in the body. Rule 934100 matches those
template tags as Node.js injection. Rule 200004 (from the recommended
ModSecurity configuration) rejects uploaded files that contain a line
starting with `--`.

All other fields (title, keywords, excerpt, ...), all other rules (SQL
injection, remote command execution, PHP injection and so on), GET requests,
other scripts (`mt-comments.cgi`, `mt-search.cgi`, ...) and the published
site stay fully checked.

The login cookie condition is not a security boundary: Movable Type checks
the session and the magic token itself. It only keeps the exclusions away
from requests that do not look like a logged-in user.

Plugins and custom fields that post their own fields are not covered and
must be tuned with
[custom rule exclusions](https://coreruleset.org/docs/concepts/false_positives_tuning/).

## Installation

For full and up to date instructions for the different available plugin
installation methods, refer to [How to Install a Plugin](https://coreruleset.org/docs/concepts/plugins/#how-to-install-a-plugin)
in the official CRS documentation.

### Renamed administration script

If `AdminScript` in `mt-config.cgi` is not `mt.cgi`, set
`tx.movabletype-rule-exclusions-plugin_admin_script` in
`movabletype-rule-exclusions-config.conf`:

```apache
SecAction \
    "id:9533020,\
    phase:1,\
    pass,\
    nolog,\
    ver:'movabletype-rule-exclusions-plugin/0.1.0',\
    setvar:'tx.movabletype-rule-exclusions-plugin_admin_script=admin.cgi'"
```

### Conditionally enable plugins for multi-application environments

For full and up to date instructions on how to conditionally enable/disable
this plugin on a multisite environment, please refer to
[Conditionally enable plugins for multi-application environments](https://coreruleset.org/docs/concepts/plugins/#conditionally-enable-plugins-for-multi-application-environments)
in the official CRS documentation.

## Testing

The regression tests in `tests/regression` use the
[go-ftw](https://github.com/coreruleset/go-ftw) format and run with the
[CRS plugin test action](https://github.com/coreruleset/crs-plugin-test-action)
on Apache (ModSecurity v2) and nginx (libmodsecurity v3).

## License

Copyright (c) 2026 futsure0 and contributors.

The plugin is distributed under Apache Software License (ASL) version 2.
Please see the enclosed LICENSE file for full details.
