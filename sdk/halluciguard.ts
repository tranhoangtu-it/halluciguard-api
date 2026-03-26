/**
 * HalluciGuard TypeScript SDK
 * AI Hallucination Firewall — validate LLM outputs in one line of code.
 *
 * @example
 * ```typescript
 * import { HalluciGuard } from 'halluciguard';
 *
 * const guard = new HalluciGuard({ apiKey: 'hg_...' });
 *
 * // Validate code
 * const result = await guard.validateCode('from os import quantum_sort', 'python');
 * console.log(result.safe); // false
 * console.log(result.issues); // [{ message: "'quantum_sort' does not exist..." }]
 *
 * // Validate text
 * const textResult = await guard.validateText('According to a 2024 study...');
 * console.log(textResult.confidence); // 0.76
 * ```
 */

// ── Types ────────────────────────────────────────────────────────

export interface HalluciGuardConfig {
  apiKey: string;
  baseUrl?: string;
  timeout?: number;
}

export type Severity = 'error' | 'warning' | 'info';

export type IssueType =
  | 'hallucinated_fact'
  | 'nonexistent_api'
  | 'wrong_signature'
  | 'deprecated_api'
  | 'invalid_import'
  | 'fabricated_reference'
  | 'inconsistent_claim'
  | 'unsupported_parameter';

export interface Issue {
  severity: Severity;
  issue_type: IssueType;
  message: string;
  line?: number | null;
  column?: number | null;
  suggestion?: string | null;
  confidence: number;
}

export interface ValidationResult {
  safe: boolean;
  confidence: number;
  issues: Issue[];
  issues_count: number;
  latency_ms: number;
  validated_at: string;
  request_id: string;
}

export interface UsageResult {
  plan: string;
  requests_used: number;
  requests_limit: number | string;
  requests_remaining: number | string;
  period: string;
}

// ── SDK Client ───────────────────────────────────────────────────

export class HalluciGuard {
  private apiKey: string;
  private baseUrl: string;
  private timeout: number;

  constructor(config: HalluciGuardConfig) {
    this.apiKey = config.apiKey;
    this.baseUrl = (config.baseUrl || 'https://halluciguard-api-deploy.vercel.app').replace(/\/$/, '');
    this.timeout = config.timeout || 30000;
  }

  async validateCode(code: string, language?: string, context?: string): Promise<ValidationResult> {
    return this._request('/api/v1/validate/code', { code, language, context });
  }

  async validateText(text: string, domain?: string, sources?: string[]): Promise<ValidationResult> {
    return this._request('/api/v1/validate/text', { text, domain, sources });
  }

  async usage(): Promise<UsageResult> {
    return this._request('/api/v1/usage', null, 'GET');
  }

  async isSafe(content: string, type: 'code' | 'text' = 'code'): Promise<boolean> {
    const result = type === 'code'
      ? await this.validateCode(content)
      : await this.validateText(content);
    return result.safe;
  }

  // ── Internal ─────────────────────────────────────────────────

  private async _request<T>(
    path: string,
    body: Record<string, any> | null,
    method: 'GET' | 'POST' = 'POST',
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const options: RequestInit = {
        method,
        headers: {
          'X-API-Key': this.apiKey,
          'Content-Type': 'application/json',
          'User-Agent': 'halluciguard-sdk/0.1.0',
        },
        signal: controller.signal,
      };

      if (body && method === 'POST') {
        options.body = JSON.stringify(body);
      }

      const response = await fetch(url, options);

      if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new HalluciGuardError(
          error.detail?.message || `API error: ${response.status}`,
          response.status,
          error.detail?.error,
        );
      }

      return response.json() as Promise<T>;
    } finally {
      clearTimeout(timeoutId);
    }
  }
}

// ── Error Class ──────────────────────────────────────────────────

export class HalluciGuardError extends Error {
  status: number;
  code?: string;

  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = 'HalluciGuardError';
    this.status = status;
    this.code = code;
  }
}

// ── Default Export ────────────────────────────────────────────────

export default HalluciGuard;
