#!/bin/bash
# -+- coding: UTF-8 -+-

set -eu

if [ -d "/codex" ] && [ ! -e "$HOME/.codex" ]; then
  ln -sT /codex $HOME/.codex
fi

HISTFILE=/history/.bash_history
touch $HISTFILE

SNIPPET="export PROMPT_COMMAND='history -a' && export HISTFILE=$HISTFILE"
echo "$SNIPPET" >> "$HOME/.bashrc"
