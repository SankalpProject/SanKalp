import { ApiError, NetworkError } from './errors';
import type { HttpClient, HttpRequest } from './HttpClient';

interface ProblemBody {
  code?: string;
  detail?: string;
  retryAfterSeconds?: number;
}

/** `fetch`-based transport with timeouts and uniform error mapping. */
export class FetchHttpClient implements HttpClient {
  constructor(
    private readonly baseUrl: string,
    private readonly timeoutMs: number,
  ) {}

  async request<T>({ method, path, body, headers }: HttpRequest): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: {
          Accept: 'application/json',
          ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
          ...headers,
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
    } catch {
      throw new NetworkError();
    } finally {
      clearTimeout(timer);
    }

    if (response.status === 204) {
      return undefined as T;
    }

    const payload = await response.json().catch(() => undefined);

    if (!response.ok) {
      const problem = (payload ?? {}) as ProblemBody;
      const retryHeader = Number(response.headers.get('Retry-After'));
      throw new ApiError(
        response.status,
        problem.code ?? 'UNKNOWN',
        problem.detail ?? 'Something went wrong.',
        problem.retryAfterSeconds ?? (Number.isFinite(retryHeader) && retryHeader > 0 ? retryHeader : undefined),
      );
    }
    return payload as T;
  }
}
