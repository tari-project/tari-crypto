#!/bin/bash
# run from the repo root

TMP=$(mktemp) || exit 1
trap 'rm -f "$TMP"' EXIT

rg -i "Copyright.*The Tari Project" --files-without-match -g '!*.{Dockerfile,asc,bat,config,config.js,css,csv,drawio,gitkeep,hbs,html,iss,json,lock,md,min.js,ps1,py,rc,scss,sh,sql,svg,toml,txt,yml}' . | sort >"$TMP"

DIFFS=$(diff -u .license.ignore "$TMP")

if [ -n "$DIFFS" ]; then
    echo "New files detected that either need copyright/license identifiers added, or they need to be added to .license.ignore"
    echo "NB: The ignore file must be sorted alphabetically!"

    echo "Diff:"
    echo "$DIFFS"
    exit 1
fi
