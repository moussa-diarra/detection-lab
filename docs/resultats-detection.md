# Résultats de détection — 8 techniques ATT&CK

Lab : Wazuh 4.14.9 (manager seul) + Sysmon v15.22 + journaux de sécurité Windows.
Rejeu : Atomic Red Team (indépendant) quand un test existe, sinon rejeu manuel de la technique.
Campagne de référence : voir docs/evidence/e-campagne-finale.txt

| # | Technique ATT&CK | Méthode de rejeu | Détecté | Règle | Source de l'événement |
|---|------------------|------------------|:-------:|-------|-----------------------|
| 1 | T1059.001 — PowerShell encodé        | Rejeu manuel (-EncodedCommand) | oui | 100110 | Sysmon EID 1 |
| 2 | T1547.001 — Clé de registre Run       | Atomic T1547.001-1             | oui | 100120 | Sysmon EID 13 |
| 3 | T1053.005 — Tâche planifiée           | Atomic T1053.005-2             | oui | 100130 | Security 4698 |
| 4 | T1136.001 — Création de compte local  | Atomic T1136.001-4             | oui | 100140 | Security 4720 |
| 5 | T1070.001 — Effacement de journaux    | Rejeu manuel (wevtutil cl)     | oui | 100150 | Eventlog 1102/104 |
| 6 | T1562.001 — Désactivation de Defender | Rejeu manuel (Set-MpPreference)| oui | 100160 | Defender 5001 |
| 7 | T1003.001 — Vidage mémoire de LSASS   | Rejeu manuel (Gestionnaire des tâches) | oui | 100170 | Sysmon EID 11 |
| 8 | T1558.003 — Kerberoasting             | Rejeu manuel (demande de ticket, DC01) | oui | 100180 | Security 4769 |

**Résultat : 8/8 techniques détectées.**

## Notes de transparence

- **T1059.001** : le test Atomic n°15 dépend d'un module (ATHTools) non installé dans le lab ;
  la technique a été rejouée manuellement avec `-EncodedCommand`, ce que la règle détecte.
- **T1070.001 et T1562.001** : aucun test Atomic disponible pour ces sous-techniques dans la
  version récupérée ; rejeu manuel de la technique.
- **T1003.001** : le vidage de LSASS par procdump a été **bloqué par Microsoft Defender**
  (preuve : docs/evidence/d-t1003-defender-block.txt). Aucun fichier .dmp n'ayant été créé,
  la règle 100170 n'a logiquement pas déclenché sur ce vecteur — la détection intervient en
  aval du blocage. La règle est validée via le Gestionnaire des tâches, où le vidage aboutit.
  Illustration de la défense en profondeur : Defender bloque, Wazuh détecterait si le blocage
  était contourné.
- **T1558.003** : joué depuis le contrôleur de domaine, faute de RAM pour un poste client
  supplémentaire (8 Go au total). L'événement 4769 est émis par le KDC sur le DC, donc la
  détection est identique ; la limite est l'absence de test de propagation depuis un client.