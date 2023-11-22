#!/usr/bin/env bash

export LANG=fr_FR.iso88591

# shellcheck disable=SC2016 disable=SC1003
sed \
	-e 's/\s*AUTO_INCREMENT\(=[0-9]\)\{0,1\}//g' \
	-e 's/\s*COMMENT\s\+.*/,/g' \
	-e '/^\s*#/d' \
	-e 's/\s*ENGINE=[^;]\+//g' \
	-e "s/\\\'/''/g" \
	-e 's/\s*\(UN\)\{0,1\}LOCK\s\+TABLES[^;]*;//g' \
	-e '/^\s*\(UNIQUE\s\+\)\{0,1\}KEY/d' \
	-e 's/\(,\s*\)\+)/)/g' \
	-e 's/)\s*unsigned/)/g' \
	-e 's/\(`[^`]\+`\)\s\+enum(\([^)]*\))/\1 CHECK(\1 in (\2))/g' \
	-e 's/\s*CHARACTER\s\+SET\s\+\w\+//g' \
	-e 's/\s*COLLATE\s\+\w\+//g' \
	-e '/^SET\s\+.*;$/d' \
	-e '/^CREATE\s\+DATABASE.*;$/d' \
	-e '/^USE\s\+.*;$/d' \
| tr '\n' '\v' \
| sed -e 's/\s*,\s*\\*)/\v)/g' \
| tr '\v' '\n'
