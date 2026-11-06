#!/usr/bin/env python3
"""Valide la structure des regles custom : XML bien forme, id >= 100000, mapping MITRE."""
import sys, xml.etree.ElementTree as ET

RULES = "rules/local_rules.xml"
errors = []

# 1. XML bien forme ? (on enveloppe car local_rules.xml a plusieurs <group> racine possibles)
try:
    with open(RULES, encoding="utf-8") as f:
        content = f.read()
    root = ET.fromstring(f"<root>{content}</root>")
except ET.ParseError as e:
    print(f"ERREUR : XML invalide dans {RULES} : {e}")
    sys.exit(1)

rules = root.findall(".//rule")
if not rules:
    print("ERREUR : aucune regle trouvee")
    sys.exit(1)

detection_rules = 0
for r in rules:
    rid = r.get("id")
    # 2. id numerique >= 100000
    if not rid or not rid.isdigit() or int(rid) < 100000:
        errors.append(f"Regle id={rid} : doit etre un nombre >= 100000")
    # 3. les regles de detection (level > 0) doivent avoir un mapping MITRE
    level = int(r.get("level", "0"))
    if level > 0:
        detection_rules += 1
        if r.find("mitre") is None:
            errors.append(f"Regle id={rid} (level {level}) : mapping <mitre> manquant")
        if r.find("description") is None:
            errors.append(f"Regle id={rid} : <description> manquante")

if errors:
    print("VALIDATION ECHOUEE :")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)

print(f"OK : {len(rules)} regles valides, {detection_rules} regles de detection avec mapping MITRE.")