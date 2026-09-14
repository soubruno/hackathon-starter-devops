const path = require('node:path');
const crypto = require('node:crypto');
const fs = require('node:fs');

/*
 * getFileHash function for use in pug templates for cache busting of frontend files
 * Computes a short content hash for a frontend file, used as a cache-busting query parameter (?v=HASH)
 * It also caches the computed hash on first use, so subsequent calls
 * for the same file skip the disk read and hash calculation
 */
const fileHashCache = new Map();

exports.getFileHash = (fileUrl, libFiles, rootDir) => {
  if (fileHashCache.has(fileUrl)) return fileHashCache.get(fileUrl);

  let filePath;
  if (libFiles && libFiles.has(fileUrl)) {
    // was the file from public/ folder or from libFiles?
    filePath = libFiles.get(fileUrl);
  } else {
    filePath = path.join('public', fileUrl.startsWith('/') ? fileUrl.slice(1) : fileUrl);
  }

  const fullPath = path.join(rootDir, filePath);

  // Se o arquivo não existir fisicamente no disco, retorna vazio em vez de estourar erro 500
  if (!fs.existsSync(fullPath)) {
    return '';
  }

  try {
    const fileBuffer = fs.readFileSync(fullPath);
    const hash = crypto
      .createHash('sha256')
      .update(fileBuffer)
      .digest('hex')
      .slice(0, 8);

    fileHashCache.set(fileUrl, hash);
    return hash;
  } catch (error) {
    return '';
  }
};

// Reset the in-memory cache (useful in tests)
exports.clearCache = () => fileHashCache.clear();