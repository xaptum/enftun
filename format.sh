#!/bin/bash

set -e

check() {
    echo \
"-------------------------------
Checking source code formatting
-------------------------------"
    local rc=0
    local sources=$(find ./src -name \*.c -type f -or -name \*.h -type f)
    for file in $sources; do
        count=$(clang-format -output-replacements-xml $file | (grep offset || true) | wc -l)
        if [ "$count" -gt "0" ]; then
            echo "✗ $file"
            rc=1
        fi
    done

    if [ "$count" -gt "0" ]; then
        echo ERROR: files are formatted incorrectly
        exit 1
    fi

    exit $rc
}

format() {
    find ./src -name \*.c -type f -or -name \*.h -type f | xargs clang-format --style=file -i
}

main() {
    case "$1" in
        check)
            check
            ;;

        format | *)
            format
            ;;

    esac

}

# Call main with all the arguments
main $@
