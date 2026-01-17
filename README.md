# AEGIS Security Toolkit

**Version 2.1** - Suite d'Analyse de Sécurité Professionnelle

AEGIS est une boîte à outils de sécurité web conçue pour l'analyse rapide et l'hygiène numérique. Développée avec un accent sur la confidentialité et la performance, elle repose sur une architecture hybride combinant un traitement côté client avec une vérification sécurisée côté serveur.

## Fonctionnalités Principales

### Analyse Réseau & Identité
*   **Intelligence IP Temps Réel** : Identification instantanée de la connectivité IP publique, de l'ASN et des détails du FAI via une résolution directe côté client pour contourner les masquages proxy.
*   **Empreinte Système** : Détection des paramètres de l'environnement local et des vecteurs de traçage du navigateur.

### Intégrité des Fichiers & Forensique
*   **Vérification Cryptographique** : Calcul côté client des hachages SHA-256 pour la validation de l'intégrité des fichiers sans nécessité de téléchargement vers le serveur.
*   **Analyse de Malware** : Intégration avec l'API VirusTotal pour la recherche sécurisée de réputation de fichiers et exécutables basée sur le hachage.
*   **Gestion des Métadonnées EXIF** : Extraction et sanitisation complète des métadonnées cachées des fichiers image pour prévenir les fuites de confidentialité.

### Utilitaires de Sécurité
*   **Générateur d'Entropie de Mots de Passe** : Création d'identifiants cryptographiquement forts avec des règles de complexité personnalisables (majuscules, symboles, longueur mixte).
*   **Détection de Fuites** : Vérification des adresses email contre les bases de données de violations connues via XposedOrNot.
*   **Intelligence des Menaces URL** : Analyse des URL cibles pour le phishing, la distribution de malwares et le score de réputation.

### Traitement de Données
*   **Génération QR Sécurisée** : Création locale de codes QR pour le transfert de données.
*   **Optimisation d'Image** : Moteur de compression haute efficacité pour les formats JPG/PNG/WEBP/PDF avec traitement local respectueux de la vie privée.
*   **Conversion de Format** : Convertisseur d'images universel supportant les formats vectoriels (SVG) et matriciels.
*   **Sanitisation de Texte** : Suppression des caractères de largeur nulle et du formatage caché utilisé dans les attaques par obfuscation.

## Architecture

Le système utilise une architecture hybride monolithique :
*   **Frontend** : JavaScript Vanilla (ES6+), HTML5, CSS3. Framework sans dépendance pour une performance et une auditabilité maximales.
*   **Backend** : Environnement Node.js / Express agissant comme une passerelle sécurisée pour la protection des tokens API et la gestion CORS.
*   **Déploiement** : Conteneurisation prête pour Docker pour un hébergement souverain.

## Déploiement

### Prérequis
*   Environnement Node.js 18+
*   Clé API VirusTotal (Standard ou Premium)

### Configuration de l'Environnement
Configurez les variables d'environnement suivantes dans votre fichier `.env` ou les paramètres de votre conteneur :
```bash


### Déploiement Docker
Le dépôt inclut un `Dockerfile` prêt pour la production.
```bash
docker build -t aegis-toolkit .
docker run -p 3000:3000 --env-file .env aegis-toolkit
```

## Politique de Confidentialité
AEGIS est conçu selon la philosophie "Privacy by Default".

***Traitement Local** : La compression, la conversion, le hachage des fichiers et la génération de mots de passe s'effectuent strictement dans le navigateur du client. Les fichiers ne sont jamais transmis au serveur pour ces opérations.

***Rétention Minimale des Données** : Le serveur agit strictement comme un proxy sans état pour les API externes d'intelligence des menaces. Aucun journal d'activité utilisateur ou de donnée analysée n'est persisté.

**Licence** : MIT

