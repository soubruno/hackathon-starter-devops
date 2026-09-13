const request = require('supertest');
const { expect } = require('chai');
const express = require('express');

// Cria uma instância de teste do Express com os middlewares principais da aplicação
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rota de status/healthcheck para teste de integração
app.get('/status', (req, res) => {
  res.status(200).json({ status: 'UP', timestamp: new Date().toISOString() });
});

// Middleware simulado de rota inexistente (404) igual ao padrão do hackathon-starter
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found', path: req.originalUrl });
});

describe('Integration Tests: Express HTTP Pipeline', () => {
  it('GET /status should return 200 OK with JSON status payload', async () => {
    const response = await request(app).get('/status');
    expect(response.status).to.equal(200);
    expect(response.body).to.have.property('status', 'UP');
    expect(response.body).to.have.property('timestamp');
  });

  it('GET /rota-inexistente should return 404 Not Found', async () => {
    const response = await request(app).get('/rota-inexistente');
    expect(response.status).to.equal(404);
    expect(response.body).to.have.property('error', 'Not Found');
    expect(response.body.path).to.equal('/rota-inexistente');
  });
});