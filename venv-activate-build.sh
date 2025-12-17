#!/bin/bash

set -euxo pipefail

if [ -z "${1:-}" ]; then
	echo "Usage: $0 <venv-path>"
	exit 1
fi

venvdir=$1

if [ ! -d "$venvdir" ]; then
	mkdir -p "$venvdir"
fi

wheels=$(mktemp -d)

cp requirements.txt "$wheels"

python -m venv "$venvdir" \
	&& . "$venvdir/bin/activate" \
	&& pip install --no-compile -r "$wheels/requirements.txt" -f "$wheels" \
	&& rm -rf "$wheels" \
	&& find . -name './*.pyc' -delete
