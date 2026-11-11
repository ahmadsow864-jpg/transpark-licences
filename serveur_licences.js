// ═══════════════════════════════════════════════════════════════════
// TRANSPARK — Serveur central de validation des licences
// A.B.D. Consulting — Amadou Sow
//
// Ce serveur est le SEUL endroit où la clé secrète SECRET_LICENCE existe
// désormais (en dehors du Générateur de licences, outil privé qui ne
// doit jamais être donné à un client). Le logiciel client (outil_logistique_v2.html
// et l'application Windows Electron) ne contient plus aucun secret : il
// envoie simplement le code machine + la clé saisie, et ce serveur répond
// si c'est valide. Corrige les vulnérabilités V-001/V-002 de l'audit.
// ═══════════════════════════════════════════════════════════════════

require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');

const SECRET_LICENCE = process.env.SECRET_LICENCE;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const PORT = process.env.PORT || 3500;

if (!SECRET_LICENCE || !ADMIN_PASSWORD || ADMIN_PASSWORD === 'CHANGEZ-MOI-AVANT-DEPLOIEMENT') {
  console.error('❌ ERREUR : définissez SECRET_LICENCE et un ADMIN_PASSWORD fort dans le fichier .env avant de démarrer.');
  process.exit(1);
}

// ─── Base de données (journal des licences / révocations) ───
const db = new Database(path.join(__dirname, 'licences.db'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS licences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    codeMachine TEXT NOT NULL,
    type TEXT NOT NULL,
    statut TEXT NOT NULL DEFAULT 'active',
    dateActivation TEXT,
    dateCreation TEXT NOT NULL DEFAULT (datetime('now')),
    derniereVerif TEXT,
    nbVerifs INTEGER NOT NULL DEFAULT 0,
    UNIQUE(codeMachine, type)
  );
`);

const FORMULES = {
  '3ANS': { label: '3 ans', jours: 1095 },
  '6ANS': { label: '6 ans', jours: 2190 },
  '8ANS': { label: '8 ans', jours: 2920 },
  'VIE': { label: 'À vie', jours: 0 }
};

function calculerCleAttendue(codeMachine, typeCode) {
  const hmac = crypto.createHmac('sha256', SECRET_LICENCE);
  hmac.update(`${codeMachine}:${typeCode}`);
  const hexa = hmac.digest('hex').toUpperCase();
  return hexa.slice(0, 16).match(/.{1,4}/g).join('-');
}

function normaliserCle(cle) {
  return (cle || '').toUpperCase().replace(/[^A-F0-9]/g, '').match(/.{1,4}/g)?.join('-') || '';
}

function normaliserCodeMachine(code) {
  return (code || '').toUpperCase().trim();
}

// ─── App Express ───
const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(cors()); // endpoints publics de licence : ouverts à tout client TRANSPARK, aucune donnée sensible renvoyée
app.use(express.json({ limit: '50kb' }));

const limiteurGeneral = rateLimit({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });
app.use('/api/', limiteurGeneral);

function middlewareAdmin(req, res, next) {
  const motDePasse = req.headers['x-admin-password'];
  if (!motDePasse || motDePasse !== ADMIN_PASSWORD) {
    return res.status(401).json({ erreur: 'Mot de passe administrateur invalide ou absent.' });
  }
  next();
}

// ─── Santé du serveur ───
app.get('/api/health', (req, res) => {
  res.json({ ok: true, service: 'TRANSPARK Licence Serveur Central', heure: new Date().toISOString() });
});

// ─── Vérifier/activer une licence (appelé par le logiciel client) ───
app.post('/api/licences/verifier', (req, res) => {
  try {
    const codeMachine = normaliserCodeMachine(req.body.codeMachine);
    const cleSaisie = normaliserCle(req.body.cle);
    if (!codeMachine || !cleSaisie) {
      return res.status(400).json({ valide: false, erreur: 'Code machine ou clé manquant.' });
    }

    let typeTrouve = null;
    for (const typeCode of Object.keys(FORMULES)) {
      if (calculerCleAttendue(codeMachine, typeCode) === cleSaisie) {
        typeTrouve = typeCode;
        break;
      }
    }

    if (!typeTrouve) {
      return res.status(200).json({ valide: false, erreur: 'Clé de licence invalide pour cet ordinateur.' });
    }

    // Vérifier la révocation / récupérer ou créer l'enregistrement
    const existante = db.prepare('SELECT * FROM licences WHERE codeMachine = ? AND type = ?').get(codeMachine, typeTrouve);
    const maintenant = new Date().toISOString();

    if (existante) {
      if (existante.statut === 'revoque') {
        return res.status(200).json({ valide: false, erreur: 'Cette licence a été révoquée par A.B.D. Consulting. Contactez le support.' });
      }
      db.prepare('UPDATE licences SET derniereVerif = ?, nbVerifs = nbVerifs + 1 WHERE id = ?').run(maintenant, existante.id);
    } else {
      db.prepare('INSERT INTO licences (codeMachine, type, statut, dateActivation, derniereVerif, nbVerifs) VALUES (?, ?, ?, ?, ?, 1)')
        .run(codeMachine, typeTrouve, 'active', maintenant, maintenant);
    }

    const dateActivationRef = existante ? existante.dateActivation : maintenant;
    const formule = FORMULES[typeTrouve];
    let dateExpiration = null;
    if (formule.jours > 0) {
      dateExpiration = new Date(new Date(dateActivationRef).getTime() + formule.jours * 86400000).toISOString();
      if (new Date() > new Date(dateExpiration)) {
        return res.status(200).json({ valide: false, erreur: `Licence expirée le ${new Date(dateExpiration).toLocaleDateString('fr-FR')}. Contactez A.B.D. Consulting pour renouveler.`, expiree: true });
      }
    }

    return res.status(200).json({
      valide: true,
      type: typeTrouve,
      formule: formule.label,
      jours: formule.jours,
      dateActivation: dateActivationRef,
      dateExpiration,
      verifieLe: maintenant
    });
  } catch (e) {
    console.error('Erreur /api/licences/verifier :', e.message);
    res.status(500).json({ valide: false, erreur: 'Erreur serveur. Réessayez plus tard.' });
  }
});

// ─── ADMIN : lister les licences ───
app.get('/api/admin/licences', middlewareAdmin, (req, res) => {
  const lignes = db.prepare('SELECT * FROM licences ORDER BY dateCreation DESC').all();
  res.json({ licences: lignes });
});

// ─── ADMIN : calculer la clé d'une licence pour un code machine + type (remplace le calcul local du Générateur) ───
app.post('/api/admin/calculer-cle', middlewareAdmin, (req, res) => {
  const codeMachine = normaliserCodeMachine(req.body.codeMachine);
  const type = (req.body.type || '').toUpperCase();
  if (!codeMachine || !FORMULES[type]) {
    return res.status(400).json({ erreur: 'Code machine ou type de formule invalide. Types valides : 3ANS, 6ANS, 8ANS, VIE.' });
  }
  const cle = calculerCleAttendue(codeMachine, type);
  res.json({ cle, codeMachine, type, formule: FORMULES[type].label });
});

// ─── ADMIN : révoquer une licence ───
app.post('/api/admin/revoquer', middlewareAdmin, (req, res) => {
  const codeMachine = normaliserCodeMachine(req.body.codeMachine);
  if (!codeMachine) return res.status(400).json({ erreur: 'Code machine manquant.' });
  const resultat = db.prepare("UPDATE licences SET statut = 'revoque' WHERE codeMachine = ?").run(codeMachine);
  res.json({ succes: true, lignesAffectees: resultat.changes });
});

// ─── ADMIN : réactiver une licence révoquée ───
app.post('/api/admin/reactiver', middlewareAdmin, (req, res) => {
  const codeMachine = normaliserCodeMachine(req.body.codeMachine);
  if (!codeMachine) return res.status(400).json({ erreur: 'Code machine manquant.' });
  const resultat = db.prepare("UPDATE licences SET statut = 'active' WHERE codeMachine = ?").run(codeMachine);
  res.json({ succes: true, lignesAffectees: resultat.changes });
});

app.use((req, res) => res.status(404).json({ erreur: 'Route inconnue.' }));

app.listen(PORT, () => {
  console.log(`✅ Serveur central de licences TRANSPARK démarré sur le port ${PORT}`);
});
