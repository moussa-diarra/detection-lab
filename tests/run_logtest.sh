#!/usr/bin/env bash
# Passe chaque fixture dans wazuh-logtest et verifie la regle attendue.
set -u
FIX=tests/fixtures
FAIL=0

# positif -> doit declencher la regle attendue
check_pos () {  # $1=fichier  $2=regle attendue
  out=$( (cat "$FIX/$1"; sleep 2) | /var/ossec/bin/wazuh-logtest 2>&1 )
  if echo "$out" | grep -q "id: '$2'"; then
    echo "OK positif : $1 -> $2"
  else
    echo "ECHEC positif : $1 n'a pas declenche $2"; FAIL=1
  fi
}
# negatif -> ne doit PAS declencher la regle
check_neg () {  # $1=fichier  $2=regle interdite
  out=$( (cat "$FIX/$1"; sleep 2) | /var/ossec/bin/wazuh-logtest 2>&1 )
  if echo "$out" | grep -q "id: '$2'"; then
    echo "ECHEC negatif : $1 a declenche $2 (faux positif)"; FAIL=1
  else
    echo "OK negatif : $1 ne declenche pas $2"
  fi
}

check_pos T1059.001_pos.json 100110
check_pos T1547.001_pos.json 100120
check_pos T1053.005_pos.json 100130
check_pos T1136.001_pos.json 100140
check_pos T1070.001_pos_1102.json 100150
check_pos T1562.001_pos.json 100160
check_pos T1003.001_pos.json 100170
check_pos T1558.003_pos.json 100180
check_neg T1059.001_neg.json 100110
check_neg T1003.001_neg.json 100170
check_neg T1558.003_neg.json 100180

exit $FAIL