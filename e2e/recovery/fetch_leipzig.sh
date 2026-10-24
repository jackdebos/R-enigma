#!/bin/sh
# Downloads a Leipzig Wortschatz German corpus and builds neutral bigram and
# trigram tables from its sentences (see README.md, "Leipzig tables").
# Usage: e2e/recovery/fetch_leipzig.sh [CORPUS]   (default: deu_news_2010_1M)
# Everything is written under e2e/recovery/data/leipzig/ (git-ignored).
# Existing files are kept: rerunning skips the download and refuses to
# replace tables, so delete data/leipzig/ by hand to start over.
set -eu

corpus=${1:-deu_news_2010_1M}
case $corpus in
    deu_*[!A-Za-z0-9_]*|'') echo "fetch_leipzig.sh: invalid corpus name: $corpus" >&2; exit 1 ;;
    deu_*) ;;
    *) echo "fetch_leipzig.sh: corpus must be a German (deu_*) corpus: $corpus" >&2; exit 1 ;;
esac

here=$(cd "$(dirname "$0")" && pwd)
out="$here/data/leipzig"
archive="$out/$corpus.tar.gz"
sentences="$out/$corpus-sentences.txt"
mkdir -p "$out"

if [ ! -f "$archive" ]; then
    curl --fail --location --silent --show-error \
        -o "$archive.part" "https://downloads.wortschatz-leipzig.de/corpora/$corpus.tar.gz"
    mv "$archive.part" "$archive"
fi

# The archive holds <corpus>-sentences.txt at its root as "id<TAB>sentence"
# lines. Extract to a file first: a pipeline would hide a tar failure.
if [ ! -s "$sentences" ]; then
    tar -xzOf "$archive" "$corpus-sentences.txt" > "$out/$corpus-raw.part"
    cut -f2- "$out/$corpus-raw.part" > "$sentences.part"
    rm -f "$out/$corpus-raw.part"
    if [ ! -s "$sentences.part" ]; then
        echo "fetch_leipzig.sh: no sentences extracted from $archive" >&2
        exit 1
    fi
    mv "$sentences.part" "$sentences"
fi

for order in 2 3; do
    case $order in 2) name=bigram ;; 3) name=trigram ;; esac
    python3 -B "$here/ngrams.py" build --order "$order" \
        --bomm-out "$out/leipzig-$name.txt" --json-out "$out/leipzig-$name.json" "$sentences"
done
echo "tables written to $out"
