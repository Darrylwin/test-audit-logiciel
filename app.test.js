const request = require("supertest");
const app = require("../src/app");

describe("POST /login", () => {
  it("retourne un token avec des identifiants valides", async () => {
    const res = await request(app)
      .post("/login")
      .send({ username: "alice", password: "alice1234" });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("token");
  });

  it("retourne 401 avec des identifiants invalides", async () => {
    const res = await request(app)
      .post("/login")
      .send({ username: "alice", password: "mauvais" });

    expect(res.status).toBe(401);
  });
});

describe("GET /users/:id", () => {
  let token;

  beforeAll(async () => {
    const res = await request(app)
      .post("/login")
      .send({ username: "bob", password: "bob5678" });
    token = res.body.token;
  });

  it("retourne le profil d'un utilisateur", async () => {
    const res = await request(app)
      .get("/users/1")
      .set("Authorization", `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("username");
  });

  it("retourne 401 sans token", async () => {
    const res = await request(app).get("/users/1");
    expect(res.status).toBe(401);
  });
});
