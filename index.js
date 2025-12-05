require("dotenv").config({ path: "./.env" });

const fs = require("fs");
const path = require("path");
const express = require("express");
const cors = require("cors");
const axios = require("axios");

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // só para teste local

// Carrega o .env manualmente
const envPath = path.resolve(__dirname, ".env");
const envData = fs.readFileSync(envPath, "utf-8");

envData.split("\n").forEach(line => {
  const match = line.match(/^([a-zA-Z_]+)=(.*)$/);
  if (match) {
    const key = match[1];
    const value = match[2].trim();
    process.env[key] = value; // força sobrescrever
  }
});

const app = express();
app.use(express.json());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS.split(",")
}));

app.post("/chat", async (req, res) => {
  const { prompt } = req.body;

  try {
    const response = await axios.post(
      process.env.HF_API_BASE,
      {
        model: process.env.MODEL,
        messages: [
          {
            role: "user",
            content: prompt
          }
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

app.listen(process.env.PORT, () => {
  console.log(`Servidor rodando na porta ${process.env.PORT}`);
  console.log("Modelo atual:", process.env.MODEL);
});