/**
 * Shannon Entropy calculation for a string.
 * High entropy indicates pseudorandom character distribution common in secrets/keys.
 *
 * @param {string} str - Input string
 * @returns {number} - Entropy in bits per character
 */
export function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;

  const frequencies = new Map();
  for (const char of str) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }

  let entropy = 0;
  const len = str.length;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Redacts a detected secret string.
 * Never exposes the full raw secret value.
 *
 * @param {string} rawSecret - The secret string detected
 * @param {string} [ruleId] - Optional rule ID for context-aware redaction
 * @returns {string} - Redacted secret string
 */
export function redactSecret(rawSecret, ruleId = '') {
  if (!rawSecret) return '***';

  const len = rawSecret.length;

  if (ruleId === 'private_key') {
    return '-----BEGIN PRIVATE KEY-----\n[REDACTED PRIVATE KEY CONTENT]\n-----END PRIVATE KEY-----';
  }

  if (rawSecret.startsWith('AKIA')) {
    return 'AKIA' + '*'.repeat(Math.max(4, len - 4));
  }

  if (rawSecret.startsWith('sk_live_')) {
    return 'sk_live_' + '*'.repeat(Math.max(4, len - 8));
  }

  if (rawSecret.startsWith('ghp_')) {
    return 'ghp_' + '*'.repeat(Math.max(4, len - 4));
  }

  if (rawSecret.startsWith('github_pat_')) {
    return 'github_pat_' + '*'.repeat(Math.max(4, len - 11));
  }

  if (len <= 6) {
    return '*'.repeat(len);
  }

  if (len <= 12) {
    return rawSecret.slice(0, 2) + '*'.repeat(len - 4) + rawSecret.slice(-2);
  }

  return rawSecret.slice(0, 4) + '*'.repeat(len - 8) + rawSecret.slice(-4);
}

/**
 * Built-in Secret Detection Rules
 */
export const SECRET_DETECTOR_RULES = [
  {
    id: 'aws_access_key',
    name: 'AWS Access Key ID',
    severity: 'CRITICAL',
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    group: 1
  },
  {
    id: 'aws_secret_key',
    name: 'AWS Secret Access Key',
    severity: 'CRITICAL',
    regex: /(?:aws_secret_access_key|aws_secret_key|aws_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    group: 1
  },
  {
    id: 'private_key',
    name: 'Private Key Block',
    severity: 'CRITICAL',
    regex: /(-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----)/g,
    group: 1
  },
  {
    id: 'stripe_api_key',
    name: 'Stripe Live Secret Key',
    severity: 'HIGH',
    regex: /\b(sk_live_[0-9a-zA-Z]{16,40})\b/g,
    group: 1
  },
  {
    id: 'github_pat',
    name: 'GitHub Personal Access Token',
    severity: 'HIGH',
    regex: /\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b/g,
    group: 1
  },
  {
    id: 'jwt_token',
    name: 'JSON Web Token (JWT)',
    severity: 'MEDIUM',
    regex: /\b(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b/g,
    group: 1
  },
  {
    id: 'bearer_token',
    name: 'Bearer Authorization Token',
    severity: 'MEDIUM',
    regex: /\bBearer\s+([A-Za-z0-9\-\._~\+\/]+=*)\b/gi,
    group: 1
  },
  {
    id: 'db_connection_string',
    name: 'Database Connection String with Credentials',
    severity: 'HIGH',
    regex: /\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s"'<>:]+:[^\s"'<>@]+@[^\s"'<>]+)\b/gi,
    group: 1
  },
  {
    id: 'env_secret',
    name: '.env File Secret Assignment',
    severity: 'HIGH',
    regex: /^\s*(?:AWS_SECRET_ACCESS_KEY|SECRET_KEY|API_KEY|PASSWORD|PRIVATE_KEY|AUTH_TOKEN|DATABASE_URL)\s*=\s*(["']?.+?["']?)\s*$/gm,
    group: 1
  },
  {
    id: 'hardcoded_password',
    name: 'Hardcoded Password Assignment',
    severity: 'HIGH',
    regex: /(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{6,})['"]/gi,
    group: 1
  }
];

/**
 * Scans a text string or file content for sensitive secrets and credentials.
 *
 * @param {string} text - The input content to scan
 * @param {Object} [options]
 * @param {boolean} [options.entropyScan=true] - Whether to perform Shannon entropy scan for random strings
 * @param {number} [options.minEntropy=4.5] - Minimum Shannon entropy threshold (bits/char)
 * @param {number} [options.minEntropyLength=16] - Minimum string length for entropy check
 * @returns {Array<Object>} - List of detected secret findings (with redacted values)
 */
export function scanSecrets(text, options = {}) {
  if (typeof text !== 'string' || text.length === 0) {
    return [];
  }

  const {
    entropyScan = true,
    minEntropy = 4.5,
    minEntropyLength = 16
  } = options;

  const findings = [];
  const lines = text.split('\n');

  // Helper to compute line and column from character index
  function getPosition(index) {
    let currentLength = 0;
    for (let l = 0; l < lines.length; l++) {
      const lineLen = lines[l].length + 1; // +1 for newline
      if (index < currentLength + lineLen) {
        return {
          line: l + 1,
          column: index - currentLength + 1
        };
      }
      currentLength += lineLen;
    }
    return { line: 1, column: 1 };
  }

  // Track matched ranges to avoid duplicate entropy alerts
  const matchedRanges = [];

  // 1. Rule-based pattern matching
  for (const rule of SECRET_DETECTOR_RULES) {
    const regex = new RegExp(rule.regex);
    let match;
    while ((match = regex.exec(text)) !== null) {
      const fullMatch = match[0];
      const secretValue = rule.group && match[rule.group] ? match[rule.group] : fullMatch;
      const startIndex = match.index + (fullMatch.indexOf(secretValue));
      const endIndex = startIndex + secretValue.length;

      matchedRanges.push([startIndex, endIndex]);

      const pos = getPosition(startIndex);
      findings.push({
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
        line: pos.line,
        column: pos.column,
        matchLength: secretValue.length,
        redactedValue: redactSecret(secretValue, rule.id)
      });
    }
  }

  // 2. High Shannon Entropy Scan
  if (entropyScan) {
    // Tokenize strings/words
    const wordRegex = /[A-Za-z0-9_\-\+\/=]{16,}/g;
    let wordMatch;

    while ((wordMatch = wordRegex.exec(text)) !== null) {
      const candidate = wordMatch[0];
      const start = wordMatch.index;
      const end = start + candidate.length;

      // Check if already caught by a pattern rule
      const alreadyCaught = matchedRanges.some(
        ([rStart, rEnd]) => start >= rStart && end <= rEnd
      );

      if (!alreadyCaught && candidate.length >= minEntropyLength) {
        const entropy = calculateShannonEntropy(candidate);
        if (entropy >= minEntropy) {
          const pos = getPosition(start);
          findings.push({
            ruleId: 'high_entropy_secret',
            ruleName: `High Entropy String (${entropy.toFixed(2)} bits/char)`,
            severity: 'MEDIUM',
            line: pos.line,
            column: pos.column,
            matchLength: candidate.length,
            entropy: Number(entropy.toFixed(2)),
            redactedValue: redactSecret(candidate, 'high_entropy_secret')
          });
        }
      }
    }
  }

  return findings;
}

/**
 * Scans text and returns a fully redacted version of the text.
 * All detected secrets are replaced in place with redacted placeholders.
 *
 * @param {string} text - Input text containing potential secrets
 * @returns {string} - Text with all detected secrets redacted
 */
export function redactText(text) {
  if (typeof text !== 'string' || text.length === 0) {
    return text;
  }

  let result = text;

  for (const rule of SECRET_DETECTOR_RULES) {
    const regex = new RegExp(rule.regex);
    result = result.replace(regex, (fullMatch, g1) => {
      const secretToRedact = g1 || fullMatch;
      const redacted = redactSecret(secretToRedact, rule.id);
      return fullMatch.replace(secretToRedact, redacted);
    });
  }

  return result;
}
