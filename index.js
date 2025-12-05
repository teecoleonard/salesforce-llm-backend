// Carrega dotenv apenas em ambiente local
if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

const express = require("express");
const cors = require("cors");
const axios = require("axios");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

// Variáveis de ambiente obrigatórias
const requiredEnv = [
  "PORT",
  "HF_API_KEY",
  "HF_API_BASE",
  "ALLOWED_ORIGINS"
];

const missingEnv = requiredEnv.filter(key => !process.env[key]);
if (missingEnv.length > 0) {
  console.error("As seguintes variáveis de ambiente estão faltando:", missingEnv.join(", "));
  process.exit(1);
}

const port = process.env.PORT || 3000;
const useThirdPartyRouter = process.env.USE_THIRD_PARTY_ROUTER === 'true';

// Desabilita verificação TLS apenas em desenvolvimento
if (process.env.NODE_ENV !== 'production') {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
}

const app = express();
app.use(express.json({ limit: '10mb' }));

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

const allowedOrigins = process.env.ALLOWED_ORIGINS.split(",").map(origin => origin.trim());
app.use(cors({
  origin: (origin, callback) => {
    // Permite requisições sem origin (Named Credentials, Postman, etc)
    if (!origin) {
      return callback(null, true);
    }
    
    // Verifica se está na lista de permitidos
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    
    // Permite domínios do Salesforce (*.salesforce.com, *.force.com, *.lightning.force.com)
    if (origin.includes('.salesforce.com') || origin.includes('.force.com') || origin.includes('.lightning.force.com')) {
      return callback(null, true);
    }
    
    console.warn(`CORS bloqueado para origem: ${origin}`);
    callback(new Error('Não permitido pelo CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'api-key']
}));

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

// Remove dados sensíveis dos logs
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

function validateApiKey(req, res, next) {
  const apiKey = req.headers['api-key'];
  
  if (!apiKey) {
    return res.status(401).json({
      error: "authentication_error",
      message: "API key não fornecida. Use o header 'api-key'."
    });
  }
  
  if (apiKey !== process.env.HF_API_KEY && !process.env.ALLOWED_API_KEYS?.split(',').includes(apiKey)) {
    return res.status(401).json({
      error: "authentication_error",
      message: "API key inválida."
    });
  }
  
  next();
}

// Validação opcional de API key (para Named Credentials sem auth)
function validateApiKeyOptional(req, res, next) {
  const apiKey = req.headers['api-key'];
  
  if (apiKey) {
    if (apiKey !== process.env.HF_API_KEY && !process.env.ALLOWED_API_KEYS?.split(',').includes(apiKey)) {
      return res.status(401).json({
        error: "authentication_error",
        message: "API key inválida."
      });
    }
  }
  
  next();
}

// Processa e otimiza mensagens: concatena múltiplas system messages em uma única
function processMessages(messages) {
  if (!Array.isArray(messages) || messages.length === 0) {
    return messages;
  }
  
  const processed = [];
  let systemContent = [];
  
  for (const msg of messages) {
    if (msg.role === 'system') {
      systemContent.push(msg.content);
    } else {
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
  
  if (systemContent.length > 0) {
    processed.push({
      role: 'system',
      content: systemContent.join('\n')
    });
  }
  
  return processed;
}

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
    defaultModel: process.env.MODEL || "Salesforce/xLAM-v0.1-r",
    useThirdPartyRouter: useThirdPartyRouter
  });
});

// Rota /chat - compatível com código Apex (formato antigo com prompt)
app.post("/chat", validateApiKeyOptional, async (req, res) => {
  console.log("Rota /chat chamada", { 
    method: req.method,
    path: req.path,
    origin: req.headers.origin,
    body: sanitizeForLogging(req.body) 
  });
  
  const { prompt, max_tokens } = req.body;

  if (!prompt || String(prompt).trim().length === 0) {
    return res.status(400).json({
      error: "validation_error",
      message: "O campo 'prompt' é obrigatório"
    });
  }

  // Converte prompt para formato messages
  const model = process.env.MODEL || req.body.model || "Salesforce/xLAM-v0.1-r";
  const messages = [
    { role: "user", content: String(prompt) }
  ];

  const payload = {
    model: model,
    messages: messages
  };

  if (max_tokens !== undefined) {
    payload.max_tokens = max_tokens;
  }

  try {
    let apiUrl = process.env.HF_API_BASE;
    
    // Ajusta URL para third-party routers (ex: Together AI)
    if (useThirdPartyRouter) {
      if (!apiUrl.endsWith('/chat/completions')) {
        apiUrl = apiUrl.endsWith('/') 
          ? `${apiUrl}chat/completions` 
          : `${apiUrl}/chat/completions`;
      }
    } else {
      // Para Hugging Face, usa o endpoint v1/chat/completions
      // Remove qualquer path existente e adiciona /v1/chat/completions
      const baseUrl = apiUrl.split('/models')[0].split('/v1')[0];
      apiUrl = baseUrl.endsWith('/') 
        ? `${baseUrl}v1/chat/completions` 
        : `${baseUrl}/v1/chat/completions`;
    }

    console.log("Chamando Hugging Face API:", {
      url: apiUrl,
      model: model,
      payloadKeys: Object.keys(payload)
    });

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

    res.json(response.data);
  } catch (err) {
    const errorMessage = err.response?.data || err.message;
    const statusCode = err.response?.status || 500;

    console.error("Erro na requisição ao Hugging Face:", sanitizeForLogging({
      status: statusCode,
      message: errorMessage,
      promptLength: String(prompt).length,
      url: apiUrl,
      payload: sanitizeForLogging(payload)
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

// Rota /chat/completions - padrão Salesforce LLM Open Connector
app.post("/chat/completions", validateApiKey, async (req, res) => {
  const { model, messages, max_tokens, temperature, n, parameters } = req.body;

  if (!model) {
    return res.status(400).json({
      error: "validation_error",
      message: "O campo 'model' é obrigatório"
    });
  }

  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({
      error: "validation_error",
      message: "O campo 'messages' é obrigatório e deve ser um array não vazio"
    });
  }

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

  // Concatena system messages
  const processedMessages = processMessages(messages);

  const payload = {
    model: model,
    messages: processedMessages
  };

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
    Object.assign(payload, parameters);
  }

  try {
    let apiUrl = process.env.HF_API_BASE;
    
    if (useThirdPartyRouter) {
      if (!apiUrl.endsWith('/chat/completions')) {
        apiUrl = apiUrl.endsWith('/') 
          ? `${apiUrl}chat/completions` 
          : `${apiUrl}/chat/completions`;
      }
    } else {
      // Para Hugging Face, usa o endpoint v1/chat/completions
      const baseUrl = apiUrl.split('/models')[0].split('/v1')[0];
      apiUrl = baseUrl.endsWith('/') 
        ? `${baseUrl}v1/chat/completions` 
        : `${baseUrl}/v1/chat/completions`;
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

app.use((req, res) => {
  res.status(404).json({
    error: "not_found",
    message: "Rota não encontrada"
  });
});

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

app.listen(port, () => {
  console.log("Servidor iniciado com sucesso!");
  console.log(`Rodando na porta ${port}`);
  console.log(`Ambiente: ${process.env.NODE_ENV || "development"}`);
  console.log(`Modelo padrão: ${process.env.MODEL || "Salesforce/xLAM-v0.1-r"}`);
  console.log(`Rate Limit: ${process.env.RATE_LIMIT_MAX || 100} req/${(parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000) / 1000 / 60}min`);
  console.log(`Third-party router: ${useThirdPartyRouter ? 'Habilitado' : 'Desabilitado'}`);
  console.log(`Rotas disponíveis: POST /chat, POST /chat/completions, GET /health`);
  if (useThirdPartyRouter) {
    console.log(`API URL: ${process.env.HF_API_BASE}`);
  }
});
