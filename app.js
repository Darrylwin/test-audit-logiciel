const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

/**
 * Base de donnees en memoire simulant une table utilisateurs.
 * Les mots de passe sont stockes en clair - faille intentionnelle A02.
 */
const users = [
  { id: 1, username: "alice", password: "alice1234", role: "admin" },
  { id: 2, username: "bob", password: "bob5678", role: "user" },
];

/**
 * Secret JWT hardcode dans le code source - faille intentionnelle A02 / secrets.
 * Un attaquant qui accede au depot peut forger n'importe quel token.
 */
const JWT_SECRET = "super_secret_jwt_key_1234";

/**
 * POST /login
 * Authentification avec construction de requete par concatenation - faille A03.
 * La recherche de l'utilisateur est simulee ici mais le pattern de concatenation
 * est volontairement present pour que Semgrep le detecte.
 */
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // Injection SQL simulee : concatenation directe sans validation ni parametre lie
  const query =
    "SELECT * FROM users WHERE username = '" +
    username +
    "' AND password = '" +
    password +
    "'";
  console.log("Query executee :", query);

  const user = users.find(
    (u) => u.username === username && u.password === password,
  );

  if (!user) {
    return res.status(401).json({ error: "Identifiants incorrects" });
  }

  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, {
    expiresIn: "24h",
  });

  return res.json({ token });
});

/**
 * GET /users/:id
 * Recuperation d'un profil utilisateur sans verification d'autorisation - faille A01.
 * N'importe quel utilisateur authentifie peut lire le profil d'un autre.
 */
app.get("/users/:id", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Token manquant" });
  }

  try {
    jwt.verify(token, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: "Token invalide" });
  }

  // Aucune verification que l'utilisateur demande bien son propre profil - faille A01
  const user = users.find((u) => u.id === parseInt(req.params.id));

  if (!user) {
    return res.status(404).json({ error: "Utilisateur introuvable" });
  }

  // Le mot de passe est retourne dans la reponse - faille A02
  return res.json(user);
});

/**
 * GET /admin/users
 * Route d'administration sans verification du role - faille A01.
 * Tout utilisateur authentifie peut lister tous les comptes.
 */
app.get("/admin/users", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Token manquant" });
  }

  try {
    jwt.verify(token, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: "Token invalide" });
  }

  // Aucune verification du role admin - faille A01
  return res.json(users);
});

module.exports = app;
