// Carrega dotenv apenas em ambiente local
if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

const express = require("express");
const cors = require("cors");
const axios = require("axios");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

// Lista de variáveis obrigatórias
const requiredEnv = [
  "PORT",
  "HF_API_KEY",
  "HF_API_BASE",
  "ALLOWED_ORIGINS"
];

// Verifica se todas estão definidas
const missingEnv = requiredEnv.filter(key => !process.env[key]);
if (missingEnv.length > 0) {
  console.error("As seguintes variáveis de ambiente estão faltando:", missingEnv.join(", "));
  process.exit(1);
}

// Porta e variáveis
const port = process.env.PORT || 3000;
const useThirdPartyRouter = process.env.USE_THIRD_PARTY_ROUTER === 'true';

// Apenas para testes locais com TLS (não recomendado em produção)
if (process.env.NODE_ENV !== 'production') {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
}

const app = express();
app.use(express.json({ limit: '10mb' }));

// Helmet.js para segurança
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: "cross-origin" },
  dnsPrefetchControl: true,
  frameguard: { action: "deny" },
  hidePoweredBy: true,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  ieNoOpen: true,
  noSniff: true,
  originAgentCluster: true,
  permittedCrossDomainPolicies: false,
  referrerPolicy: { policy: "no-referrer" },
  xssFilter: true,
}));

// Configura CORS
const allowedOrigins = process.env.ALLOWED_ORIGINS.split(",").map(origin => origin.trim());
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Não permitido pelo CORS'));
    }
  },
  credentials: true
}));

// Configuração de Rate Limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  message: {
    error: "rate_limit_exceeded",
    message: "Muitas requisições. Tente novamente mais tarde."
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(limiter);

// Função para sanitizar logs (remove dados sensíveis)
function sanitizeForLogging(data) {
  if (typeof data !== 'object' || data === null) {
    return data;
  }
  
  const sanitized = { ...data };
  const sensitiveKeys = ['api-key', 'authorization', 'api_key', 'token', 'password', 'secret'];
  
  for (const key in sanitized) {
    const lowerKey = key.toLowerCase();
    if (sensitiveKeys.some(sk => lowerKey.includes(sk))) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof sanitized[key] === 'object') {
      sanitized[key] = sanitizeForLogging(sanitized[key]);
    }
  }
  
  return sanitized;
}

// Middleware de logging sanitizado
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logData = {
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip
    };
    console.log(JSON.stringify(sanitizeForLogging(logData)));
  });
  next();
});

// Middleware de validação de API key
function validateApiKey(req, res, next) {
  const apiKey = req.headers['api-key'];
  
  if (!apiKey) {
    return res.status(401).json({
      error: "authentication_error",
      message: "API key não fornecida. Use o header 'api-key'."
    });
  }
  
  // Valida se a API key corresponde à chave configurada
  // Em produção, você pode querer validar contra um banco de dados
  if (apiKey !== process.env.HF_API_KEY && !process.env.ALLOWED_API_KEYS?.split(',').includes(apiKey)) {
    return res.status(401).json({
      error: "authentication_error",
      message: "API key inválida."
    });
  }
  
  next();
}

// Função para processar e otimizar mensagens
function processMessages(messages) {
  if (!Array.isArray(messages) || messages.length === 0) {
    return messages;
  }
  
  const processed = [];
  let systemContent = [];
  
  // Separa system messages e outras mensagens
  for (const msg of messages) {
    if (msg.role === 'system') {
      systemContent.push(msg.content);
    } else {
      // Se encontrou uma mensagem não-system e há system messages acumuladas
      if (systemContent.length > 0) {
        processed.push({
          role: 'system',
          content: systemContent.join('\n')
        });
        systemContent = [];
      }
      processed.push(msg);
    }
  }
  
  // Se sobrou system messages no final
  if (systemContent.length > 0) {
    processed.push({
      role: 'system',
      content: systemContent.join('\n')
    });
  }
  
  return processed;
}

// Endpoint de Health Check
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
    useThirdPartyRouter: useThirdPartyRouter
  });
});

// Rota principal de chat completions (padrão Salesforce LLM Open Connector)
app.post("/chat/completions", validateApiKey, async (req, res) => {
  const { model, messages, max_tokens, temperature, n, parameters } = req.body;

  // Validação do modelo
  if (!model) {
    return res.status(400).json({
      error: "validation_error",
      message: "O campo 'model' é obrigatório"
    });
  }

  // Validação das mensagens
  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({
      error: "validation_error",
      message: "O campo 'messages' é obrigatório e deve ser um array não vazio"
    });
  }

  // Valida cada mensagem
  for (const msg of messages) {
    if (!msg.role || !msg.content) {
      return res.status(400).json({
        error: "validation_error",
        message: "Cada mensagem deve ter 'role' e 'content'"
      });
    }
    
    if (!['system', 'user', 'assistant'].includes(msg.role)) {
      return res.status(400).json({
        error: "validation_error",
        message: "O 'role' deve ser 'system', 'user' ou 'assistant'"
      });
    }
    
    if (typeof msg.content !== 'string') {
      return res.status(400).json({
        error: "validation_error",
        message: "O 'content' deve ser uma string"
      });
    }
  }

  // Processa mensagens (concatena system messages)
  const processedMessages = processMessages(messages);

  // Prepara o payload para Hugging Face
  const payload = {
    model: model,
    messages: processedMessages
  };

  // Adiciona parâmetros opcionais
  if (max_tokens !== undefined) {
    payload.max_tokens = max_tokens;
  }
  if (temperature !== undefined) {
    payload.temperature = temperature;
  }
  if (n !== undefined) {
    payload.n = n;
  }
  if (parameters) {
    if (parameters.top_p !== undefined) {
      payload.top_p = parameters.top_p;
    }
    // Adiciona outros parâmetros se necessário
    Object.assign(payload, parameters);
  }

  try {
    // Determina a URL base da API
    let apiUrl = process.env.HF_API_BASE;
    
    // Se usar third-party router, adiciona o path de chat completions
    if (useThirdPartyRouter) {
      if (!apiUrl.endsWith('/chat/completions')) {
        apiUrl = apiUrl.endsWith('/') 
          ? `${apiUrl}chat/completions` 
          : `${apiUrl}/chat/completions`;
      }
    }

    const response = await axios.post(
      apiUrl,
      payload,
      {
        headers: {
          Authorization: `Bearer ${process.env.HF_API_KEY}`,
          "Content-Type": "application/json"
        },
        timeout: parseInt(process.env.HF_API_TIMEOUT) || 30000
      }
    );

    // Retorna a resposta do Hugging Face (já está no formato correto)
    res.json(response.data);
  } catch (err) {
    const errorMessage = err.response?.data || err.message;
    const statusCode = err.response?.status || 500;

    console.error("Erro na requisição ao Hugging Face:", sanitizeForLogging({
      status: statusCode,
      message: errorMessage,
      model: model,
      messagesCount: messages.length
    }));

    if (err.code === 'ECONNABORTED' || err.code === 'ETIMEDOUT') {
      return res.status(504).json({
        error: "timeout_error",
        message: "A requisição ao modelo LLM expirou. Tente novamente."
      });
    }

    if (statusCode === 401 || statusCode === 403) {
      return res.status(500).json({
        error: "authentication_error",
        message: "Erro de autenticação com a API do Hugging Face"
      });
    }

    if (statusCode === 429) {
      return res.status(429).json({
        error: "rate_limit_exceeded",
        message: "Limite de requisições ao Hugging Face excedido"
      });
    }

    res.status(statusCode >= 400 && statusCode < 500 ? statusCode : 500).json({
      error: "hf_error",
      message: "Erro ao processar requisição com o modelo LLM",
      detail: errorMessage
    });
  }
});

// Middleware de tratamento de erros 404
app.use((req, res) => {
  res.status(404).json({
    error: "not_found",
    message: "Rota não encontrada"
  });
});

// Middleware de tratamento de erros gerais
app.use((err, req, res, next) => {
  console.error("Erro não tratado:", sanitizeForLogging({
    message: err.message,
    stack: process.env.NODE_ENV !== 'production' ? err.stack : undefined
  }));
  res.status(500).json({
    error: "internal_server_error",
    message: "Erro interno do servidor"
  });
});

// Inicializa o servidor
app.listen(port, () => {
  console.log("Servidor iniciado com sucesso!");
  console.log(`Rodando na porta ${port}`);
  console.log(`Ambiente: ${process.env.NODE_ENV || "development"}`);
  console.log(`Rate Limit: ${process.env.RATE_LIMIT_MAX || 100} req/${(parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000) / 1000 / 60}min`);
  console.log(`Third-party router: ${useThirdPartyRouter ? 'Habilitado' : 'Desabilitado'}`);
  if (useThirdPartyRouter) {
    console.log(`API URL: ${process.env.HF_API_BASE}`);
  }
});
