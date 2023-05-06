#!/bin/sh

SCRIPT_DIR="$(dirname "$0")"

URLS=" \
    https://standards-oui.ieee.org/oui/oui.csv
    https://standards-oui.ieee.org/cid/cid.csv
    https://standards-oui.ieee.org/iab/iab.csv
    https://standards-oui.ieee.org/oui28/mam.csv
    https://standards-oui.ieee.org/oui36/oui36.csv
"

DL_CMD=

if which curl 2>&1 >/dev/null; then
    DL_CMD="curl -C - -L -o"
elif which wget 2>&1 >/dev/null; then
    DL_CMD="wget -c -O"
else
    echo "Unable to find curl or wget for downloading!" >&2
    exit 1
fi

for URL in ${URLS}; do
    FNAME="$(basename "${URL}")"
    ${DL_CMD} "${SCRIPT_DIR}/${FNAME}.tmp" "${URL}" || exit 1
    mv "${SCRIPT_DIR}/${FNAME}.tmp" "${SCRIPT_DIR}/${FNAME}"
done
