const { Redis } = require('@upstash/redis');
const crypto = require('crypto');

console.log('=== API 启动 ===');
console.log('KV_REST_API_URL 存在:', !!process.env.KV_REST_API_URL);
console.log('KV_REST_API_TOKEN 存在:', !!process.env.KV_REST_API_TOKEN);

const redisUrl = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const redisToken = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

let redis;
try {
  redis = new Redis({
    url: redisUrl,
    token: redisToken,
  });
  console.log('✅ Redis 初始化成功');
} catch (err) {
  console.error('❌ Redis 初始化失败:', err.message);
}

const LEDGER_KEY = 'ledger:transactions';

const EXPECTED_CIPHER = '7m4QqlrBKUEnOARiXTDERoTjgn0rNyNFMBAoGHBn59s=';

function getKeyFromPassword(password) {
  let key = Buffer.from(password, 'utf8');
  if (key.length > 16) {
    key = key.slice(0, 16);
  } else if (key.length < 16) {
    const padded = Buffer.alloc(16, 0);
    key.copy(padded);
    key = padded;
  }
  return key;
}

function aesEncrypt(plaintext, password) {
  const key = getKeyFromPassword(password);
  const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
  cipher.setAutoPadding(false);

  let buffer = Buffer.from(plaintext, 'utf8');
  const blockSize = 16;
  const padding = (blockSize - (buffer.length % blockSize)) % blockSize;
  if (padding > 0) {
    const padded = Buffer.alloc(buffer.length + padding, 0);
    buffer.copy(padded);
    buffer = padded;
  }

  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  return encrypted.toString('base64');
}

function aesDecrypt(encryptedBase64, password) {
  const key = getKeyFromPassword(password);
  const decipher = crypto.createDecipheriv('aes-128-ecb', key, null);
  decipher.setAutoPadding(false);

  const encrypted = Buffer.from(encryptedBase64, 'base64');
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

  let i = decrypted.length - 1;
  while (i >= 0 && decrypted[i] === 0) i--;
  const result = decrypted.slice(0, i + 1);
  return result.toString('utf8');
}

function safeParse(data) {
  if (!data) return null;
  try {
    const parsed = JSON.parse(data);
    if (Array.isArray(parsed)) return parsed;
    return null;
  } catch (_) {
    return null;
  }
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Password');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    if (!redis) {
      throw new Error('Redis 未正确初始化');
    }

    const password = req.headers['x-password'];
    if (!password) {
      return res.status(401).json({ error: '未提供密码' });
    }

    const testCipher = aesEncrypt('Password is correct.', password);
    if (testCipher !== EXPECTED_CIPHER) {
      console.warn('❌ 密码错误');
      return res.status(403).json({ error: '密码错误' });
    }

    let rawData = await redis.get(LEDGER_KEY);
    let transactions = [];

    if (rawData !== null && rawData !== undefined) {
      let decryptedJson = null;
      let isEncrypted = false;
      let parseOk = false;

      try {
        const decryptedStr = aesDecrypt(rawData, password);
        const parsed = JSON.parse(decryptedStr);
        if (Array.isArray(parsed)) {
          decryptedJson = parsed;
          isEncrypted = true;
          parseOk = true;
        }
      } catch (e) {
        console.log('解密失败，尝试作为未加密 JSON 解析');
        const parsed = safeParse(rawData);
        if (Array.isArray(parsed)) {
          decryptedJson = parsed;
          isEncrypted = false;
          parseOk = true;
        }
      }

      if (!parseOk) {
        console.error('❌ 存储数据无法解析（既非加密也非有效明文JSON），拒绝操作');
        return res.status(500).json({
          error: '存储数据已损坏，无法读取。请联系管理员或尝试手动恢复备份。'
        });
      }

      transactions = decryptedJson;

      if (!isEncrypted) {
        console.log('🔐 发现未加密数据，正在加密存储...');
        const encrypted = aesEncrypt(JSON.stringify(transactions), password);
        await redis.set(LEDGER_KEY, encrypted);
        try {
          const verify = aesDecrypt(encrypted, password);
          JSON.parse(verify);
          console.log('✅ 加密迁移成功');
        } catch (err) {
          console.error('❌ 加密迁移后验证失败:', err);
          await redis.set(LEDGER_KEY, JSON.stringify(transactions));
          console.warn('⚠️ 已回退到明文存储');
        }
      }
    } else {
      transactions = [];
    }

    if (req.method === 'GET') {
      console.log(`📥 GET /api/transactions (${transactions.length} 条)`);
      return res.status(200).json({ transactions });
    }

    if (req.method === 'POST') {
      console.log('📝 POST /api/transactions');
      const { description, amount, type } = req.body || {};
      if (!amount || amount <= 0) {
        return res.status(400).json({ error: '金额必须大于0' });
      }
      if (!['income', 'expense'].includes(type)) {
        return res.status(400).json({ error: '类型必须是 income 或 expense' });
      }

      const newTx = {
        id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
        description: description || '未命名',
        amount: parseFloat(amount),
        type,
        createdAt: Date.now()
      };
      transactions.push(newTx);

      const encrypted = aesEncrypt(JSON.stringify(transactions), password);
      await redis.set(LEDGER_KEY, encrypted);
      console.log(`✅ 添加记录: ${newTx.description} ${newTx.amount}`);

      return res.status(201).json({ transaction: newTx });
    }

    if (req.method === 'DELETE') {
      console.log('🗑️ DELETE /api/transactions');
      const pathParts = req.url.split('/').filter(part => part.length > 0);
      const id = pathParts[pathParts.length - 1];

      if (id === 'transactions' || pathParts.length <= 2) {
        transactions = [];
        const encrypted = aesEncrypt(JSON.stringify(transactions), password);
        await redis.set(LEDGER_KEY, encrypted);
        console.log('🗑️ 已清空所有记录');
        return res.status(200).json({ success: true });
      }

      const filtered = transactions.filter(tx => tx.id !== id);
      if (filtered.length === transactions.length) {
        return res.status(404).json({ error: '记录不存在', requestedId: id });
      }
      transactions = filtered;
      const encrypted = aesEncrypt(JSON.stringify(transactions), password);
      await redis.set(LEDGER_KEY, encrypted);
      console.log(`✅ 删除记录: ${id}`);
      return res.status(200).json({ success: true });
    }

    return res.status(405).json({ error: 'Method Not Allowed' });

  } catch (error) {
    console.error('❌ API 错误:', error);
    // 注意：这里捕获的是运行时异常，不会导致数据清空（因为数据已在之前解析成功或返回错误）
    return res.status(500).json({ error: error.message });
  }
};
