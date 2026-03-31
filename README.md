# TP3 — Systèmes d'Exploitation (EISE S8)

Travaux pratiques sur la programmation système en C sous Linux.

## Contenu

- **biceps.c** — Application multi-threadée (pthreads) avec liste de contacts partagée, serveur UDP et serveur TCP pour le partage de fichiers.
- **TCP_MT/** — Serveur TCP multi-threadé (`servtcp_mt.c`) et client TCP (`clitcp.c`).
- **LIP4/** — Exercices sur les sockets (`lip4.c`).

## Compilation

```bash
# biceps
make

# Avec traces de débogage
make trace

# TCP multi-threadé
cd TCP_MT && make
```

## Dépendances

- GCC
- pthreads (`-lpthread`)