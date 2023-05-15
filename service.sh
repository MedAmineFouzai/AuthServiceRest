#!/bin/bash
while getopts 'bwc:' OPTION; do
  case "$OPTION" in
    b)
      cargo build --release
      ;;
    w)
      cargo watch -x run
      ;;
    c)
        cargo clean
      ;;
    ?)
      echo "script usage: $(basename service) [-b build] [-w watch] [-c clean]" >&2
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"