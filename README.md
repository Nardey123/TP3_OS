NOM: EYNARD
PRENOM: Leo

# TP3 — Systèmes d'Exploitation (EISE S8)

## Structure du code

- **biceps.c** — Application principale. Contient :
  - Une liste chaînée de contacts (pseudo + IP) protégée par mutex
  - Un thread serveur UDP (protocole BEUIP : annonce, réponse, message)
  - Un thread serveur TCP (partage de fichiers depuis `pub/`)
  - Un shell interactif dans `main()`

- **TCP_MT/** — Exercice serveur TCP multi-threadé (`servtcp_mt.c`) et client (`clitcp.c`)
- **LIP4/** — Exercice sur les interfaces réseau (`lip4.c`)

## Compilation

```bash
make                # produit ./biceps
make memory-leak    # produit ./biceps-memory-leaks (avec -g -O0 pour valgrind)
make clean          # supprime les binaires
```

## Utilisation

```
./biceps
beuip start <pseudo>              -- rejoindre le réseau
beuip stop                        -- quitter le réseau
beuip list                        -- lister les contacts connectés
beuip message <pseudo> <message>  -- message privé
beuip message all <message>       -- message à tous
beuip ls <pseudo>                 -- fichiers publics d'un contact
beuip get <pseudo> <fichier>      -- télécharger un fichier
```

## Vérification des fuites mémoire

```bash
make memory-leak
valgrind --leak-check=full --track-origins=yes --errors-for-leak-kinds=all \
         --error-exitcode=1 ./biceps-memory-leaks
```
