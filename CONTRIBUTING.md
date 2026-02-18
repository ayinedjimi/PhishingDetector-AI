# Contributing / Contribuer

[🇫🇷 Français](#fr) | [🇬🇧 English](#en)

---

<a name="fr"></a>
## 🇫🇷 Guide de contribution

Merci de votre intérêt pour ce projet ! Les contributions sont les bienvenues et appréciées.

### Comment contribuer

1. **Forkez** le dépôt sur GitHub
2. **Clonez** votre fork localement :
   ```bash
   git clone https://github.com/votre-utilisateur/nom-du-repo.git
   cd nom-du-repo
   ```
3. **Créez une branche** descriptive pour votre modification :
   ```bash
   git checkout -b feature/ma-nouvelle-fonctionnalite
   ```
4. **Effectuez vos modifications** en respectant les conventions ci-dessous
5. **Commitez** vos changements en suivant la convention de commits
6. **Poussez** votre branche :
   ```bash
   git push origin feature/ma-nouvelle-fonctionnalite
   ```
7. **Ouvrez une Pull Request** vers la branche `main`

### Style de code

Ce projet suit des standards de qualité stricts pour Python :

- **Formatage** : [Black](https://github.com/psf/black) — le formateur de code sans compromis
  ```bash
  black .
  ```
- **Typage statique** : [Mypy](https://mypy-lang.org/) — toutes les fonctions publiques doivent être annotées
  ```bash
  mypy .
  ```
- **Linting** : [Pylint](https://pylint.org/) — score minimum requis : **8/10**
  ```bash
  pylint src/
  ```

Avant de soumettre une PR, assurez-vous que les trois outils passent sans erreur.

### Convention de commits

Ce projet utilise [Conventional Commits](https://www.conventionalcommits.org/fr/) :

| Préfixe     | Utilisation                          |
|-------------|--------------------------------------|
| `feat:`     | Nouvelle fonctionnalité              |
| `fix:`      | Correction de bug                    |
| `docs:`     | Documentation uniquement             |
| `style:`    | Formatage, sans changement de code   |
| `refactor:` | Refactorisation du code              |
| `test:`     | Ajout ou modification de tests       |
| `chore:`    | Maintenance, dépendances, CI/CD      |

**Exemples :**
```
feat: ajouter l'analyse des logs Apache
fix: corriger le parsing des dates ISO 8601
docs: mettre à jour le guide d'installation
```

### Processus de Pull Request

1. **Description** : décrivez clairement ce que fait votre PR et pourquoi
2. **Tests** : ajoutez ou mettez à jour les tests unitaires correspondants
3. **Review** : au moins une approbation est requise avant le merge
4. **CI** : tous les checks doivent passer (linting, tests, typage)

### Signaler un bug

Si vous trouvez un bug, ouvrez une **Issue** en incluant :

```
**Description du bug**
Description claire et concise du problème.

**Étapes pour reproduire**
1. Aller à '...'
2. Exécuter '...'
3. Observer l'erreur

**Comportement attendu**
Ce qui devrait se passer.

**Comportement actuel**
Ce qui se passe réellement.

**Environnement**
- OS : [ex. Ubuntu 22.04]
- Python : [ex. 3.11]
- Version du projet : [ex. 1.0.0]

**Captures d'écran / Logs**
Si applicable, ajoutez des captures ou extraits de logs.
```

### Proposer une fonctionnalité

Pour proposer une nouvelle fonctionnalité, ouvrez une **Issue** avec :

```
**Description de la fonctionnalité**
Description claire de la fonctionnalité souhaitée.

**Motivation**
Pourquoi cette fonctionnalité serait utile ?

**Solution proposée**
Comment envisagez-vous l'implémentation ?

**Alternatives considérées**
Avez-vous envisagé d'autres approches ?
```

### Code de conduite

En participant à ce projet, vous vous engagez à :

- Faire preuve de **respect** envers tous les participants
- Accepter les **critiques constructives** avec ouverture
- Vous concentrer sur ce qui est **bénéfique pour la communauté**
- Faire preuve d'**empathie** envers les autres contributeurs
- **Aucune forme** de harcèlement, discrimination ou comportement inapproprié ne sera tolérée

Tout manquement au code de conduite peut entraîner l'exclusion du projet.

### Contact

Pour toute question relative aux contributions :
📧 **contact@ayinedjimi-consultants.fr**

---

<a name="en"></a>
## 🇬🇧 Contributing Guide

Thank you for your interest in this project! Contributions are welcome and appreciated.

### How to Contribute

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/your-username/repo-name.git
   cd repo-name
   ```
3. **Create a descriptive branch** for your changes:
   ```bash
   git checkout -b feature/my-new-feature
   ```
4. **Make your changes** following the conventions below
5. **Commit** your changes following the commit convention
6. **Push** your branch:
   ```bash
   git push origin feature/my-new-feature
   ```
7. **Open a Pull Request** targeting the `main` branch

### Code Style

This project follows strict quality standards for Python:

- **Formatting**: [Black](https://github.com/psf/black) — the uncompromising code formatter
  ```bash
  black .
  ```
- **Static typing**: [Mypy](https://mypy-lang.org/) — all public functions must be type-annotated
  ```bash
  mypy .
  ```
- **Linting**: [Pylint](https://pylint.org/) — minimum required score: **8/10**
  ```bash
  pylint src/
  ```

Before submitting a PR, make sure all three tools pass without errors.

### Commit Convention

This project uses [Conventional Commits](https://www.conventionalcommits.org/en/):

| Prefix      | Usage                                |
|-------------|--------------------------------------|
| `feat:`     | New feature                          |
| `fix:`      | Bug fix                              |
| `docs:`     | Documentation only                   |
| `style:`    | Formatting, no code change           |
| `refactor:` | Code refactoring                     |
| `test:`     | Adding or modifying tests            |
| `chore:`    | Maintenance, dependencies, CI/CD     |

**Examples:**
```
feat: add Apache log analysis
fix: correct ISO 8601 date parsing
docs: update installation guide
```

### Pull Request Process

1. **Description**: clearly describe what your PR does and why
2. **Tests**: add or update the corresponding unit tests
3. **Review**: at least one approval is required before merging
4. **CI**: all checks must pass (linting, tests, typing)

### Reporting a Bug

If you find a bug, open an **Issue** including:

```
**Bug Description**
A clear and concise description of the problem.

**Steps to Reproduce**
1. Go to '...'
2. Run '...'
3. Observe the error

**Expected Behavior**
What should happen.

**Actual Behavior**
What actually happens.

**Environment**
- OS: [e.g. Ubuntu 22.04]
- Python: [e.g. 3.11]
- Project version: [e.g. 1.0.0]

**Screenshots / Logs**
If applicable, add screenshots or log excerpts.
```

### Proposing a Feature

To propose a new feature, open an **Issue** with:

```
**Feature Description**
A clear description of the desired feature.

**Motivation**
Why would this feature be useful?

**Proposed Solution**
How do you envision the implementation?

**Alternatives Considered**
Have you considered other approaches?
```

### Code of Conduct

By participating in this project, you agree to:

- Show **respect** towards all participants
- Accept **constructive criticism** with openness
- Focus on what is **beneficial for the community**
- Show **empathy** towards other contributors
- **No form** of harassment, discrimination, or inappropriate behavior will be tolerated

Any violation of the code of conduct may result in exclusion from the project.

### Contact

For any questions regarding contributions:
📧 **contact@ayinedjimi-consultants.fr**

---

*Maintained by Ayi NEDJIMI — [ayinedjimi-consultants.fr](https://ayinedjimi-consultants.fr)*
