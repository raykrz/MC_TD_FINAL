## 📝 Présentation du Projet
Ce module est une application autonome de **Cyber Threat Intelligence (CTI)** dédiée à la surveillance d'un périmètre d'actifs informatiques. Il analyse de manière continue le catalogue des vulnérabilités de l'ANSSI, isole les menaces à criticité élevée ou critique et génère automatiquement des notifications d'alerte par e-mail si une technologie du parc client est affectée.

---

## 🛠️ Prérequis d'Installation

L'application a été optimisée pour être extrêmement légère afin de pouvoir s'exécuter sur des environnements dotés de capacités matérielles réduites.

### Dépendance Python
Assurez-vous de disposer de Python 3.x, puis installez l'unique bibliothèque nécessaire à la manipulation des données (Pandas) :
```bash
pip install pandas

🚀 Comment Lancer l'Application
Rassemblez les fichiers email_alert.py, config.py ainsi que le fichier de données nettoyées donnees_consolidees.csv au sein du même dossier.

Ouvrez un terminal de commande dans ce répertoire.

Exécutez le script d'alerte à l'aide de la commande suivante :
python email_alert.py

⚠️ Points de Vigilance et Sécurité
Authentification SMTP (Envoi Réel) : Pour activer l'envoi réel des messages via un fournisseur tiers comme Gmail, les protocoles standards de sécurité interdisent l'usage du mot de passe de compte classique. Il est nécessaire de générer un "Mot de passe d'application" depuis les options de sécurité de votre compte de messagerie et de reporter ce jeton dans le fichier config.py.

Résilience et Mode Simulation (Fallback) : Dans le cas où les identifiants SMTP resteraient vides, ou si un pare-feu réseau venait à bloquer le port de communication sécurisé (port 465), le programme bascule instantanément en Mode Simulation. L'e-mail formaté et structuré est alors affiché directement dans le terminal hôte, ce qui garantit la continuité de l'analyse et protège les jetons d'accès.
