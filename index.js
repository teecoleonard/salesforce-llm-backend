// Carrega dotenv apenas em ambiente local
if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

const express = require("express");
const cors = require("cors");
const axios = require("axios");

// Lista de variáveis obrigatórias
const requiredEnv = [
  "PORT",
  "HF_API_KEY",
  "HF_API_BASE",
  "MODEL",
  "ALLOWED_ORIGINS"
];

// Verifica se todas estão definidas
const missingEnv = requiredEnv.filter(key => !process.env[key]);
if (missingEnv.length > 0) {
  console.error("As seguintes variáveis de ambiente estão faltando:", missingEnv.join(", "));
  process.exit(1); // Encerra a aplicação
}

// Porta e variáveis
const port = process.env.PORT || 3000;

// Apenas para testes locais com TLS (não recomendado em produção)
if (process.env.NODE_ENV !== 'production') {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
}

const app = express();
app.use(express.json());

// Configura CORS
const allowedOrigins = process.env.ALLOWED_ORIGINS.split(",");
app.use(cors({
  origin: allowedOrigins
}));

// Rota principal
app.post("/chat", async (req, res) => {
  const { prompt } = req.body;

  try {
    const response = await axios.post(
      process.env.HF_API_BASE,
      {
        model: process.env.MODEL,
        messages: [
          { role: "user", content: prompt }
        ]
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.HF_API_KEY}`,
          "Content-Type": "application/json"
        }
      }
    );

    res.json(response.data);
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).json({ error: "hf_error", detail: err.response?.data || err.message });
  }
});

// Inicializa o servidor
app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
  console.log("Modelo atual:", process.env.MODEL);
});
