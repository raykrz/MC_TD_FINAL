# -*- coding: utf-8 -*-
"""
Created on Mon Jun 15 19:19:53 2026

@author: hadil
"""

import smtplib
from email.mime.text import MIMEText
import pandas as pd

# Liste des produits/éditeurs que le client possède et veut surveiller
CLIENT_PRODUCTS = ["Linux", "Microsoft", "Apache"]

# Coordonnées pour l'envoi d'email (Gmail exige un "Mot de passe d'application" spécifique)
CREDENTIALS = {
    "expediteur": "votre.email@gmail.com",
    "destinataire": "email.du.client@example.com",
    "mot_de_passe": "votre_mot_de_passe_ou_cle_api"
}

def envoyer_alerte_email_reelle(subject, body):
    """
    Tente d'envoyer l'e-mail via le serveur SMTP. 
    Si les identifiants sont faux ou non configurés, affiche le mail dans la console
    pour éviter de faire planter l'application du projet.
    """
    expediteur = CREDENTIALS["expediteur"]
    destinataire = CREDENTIALS["destinataire"]
    mot_de_passe = CREDENTIALS["mot_de_passe"]
    
    msg = MIMEText(body, 'plain', 'utf-8')
    msg['From'] = expediteur
    msg['To'] = destinataire
    msg['Subject'] = subject

    try:
        # Tentative de connexion sécurisée au serveur SMTP de Gmail (Port 465)
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(expediteur, mot_de_passe)
            server.sendmail(expediteur, destinataire, msg.as_string())
        print("📨 Email d'alerte envoyé avec succès au client !")
    except Exception as e:
        # Stratégie de repli exigée par le prof : Affichage si échec d'envoi réel
        print("\n[📢 VIGILANCE - MODE SIMULATION ACTIVE]")
        print(f"Raison de la simulation : Connexion SMTP impossible ({e})")
        print("-" * 50)
        print(f"📧 SUJET : {subject}")
        print(f"📝 CORPS :\n{body}")
        print("-" * 50)

def verifier_csv_et_notifier(csv_path="donnees_consolidees.csv"):
    
    print("\n Analyse du catalogue de vulnérabilités pour le client...")
    
    # Lecture de votre fichier consolidé
    df = pd.read_csv(csv_path)
    
    # CORRECTION ICI : Changement de "Severite" par "Base Severity" et "Élevée" par "Elevee"
    df_critique = df[df["Base Severity"].isin(["Critique", "Elevee"])]
    
    alertes_declenchees = 0
    
    for _, ligne in df_critique.iterrows():
        editeur = str(ligne["Editeur"])
        
        # Vérification si l'éditeur de la faille est dans la liste du client
        if any(prod.lower() in editeur.lower() for prod in CLIENT_PRODUCTS):
            
            sujet = f"[ALERTE SÉCURITÉ ANSSI] - Menace majeure détectée sur {editeur}"
            
            # CORRECTION ICI : Remplacement de ligne['Severite'] par ligne['Base Severity']
            corps = f"""Bonjour,

Une alerte de sécurité critique de l'ANSSI vient d'être détectée concernant un produit de votre parc informatique.

DÉTAILS :
- Éditeur : {editeur}
- Type de menace : {ligne['Type']}
- Niveau de sévérité : {ligne['Base Severity']}
- Score CVSS : {ligne['CVSS']}/10

Veuillez appliquer les correctifs ou les restrictions d'accès au plus vite.

Cordialement,
Votre Service Cyber Threat Intelligence (CTI)."""
            
            # Envoi ou affichage
            envoyer_alerte_email_reelle(subject=sujet, body=corps)
            alertes_declenchees += 1
            
            # On s'arrête après 1 alerte pour l'exemple pour ne pas spammer la console
            break 
            
    if alertes_declenchees == 0:
        print("[✓] Analyse terminée : Aucun de vos produits n'est affecté par une faille critique récente.")

# --- Lancement du test ---
if __name__ == "__main__":
    verifier_csv_et_notifier()
