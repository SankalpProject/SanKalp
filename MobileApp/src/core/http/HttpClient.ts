export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export interface HttpRequest {
  method: HttpMethod;
  path: string;
  body?: unknown;
  headers?: Record<string, string>;
}

/**
 * Abstraction over the network (Dependency Inversion).
 * Features depend on this interface, never on `fetch` directly, so transports can be swapped or decorated
 * (auth, retries, tracing) and features can be tested with fakes.
 */
export interface HttpClient {
  request<T>(request: HttpRequest): Promise<T>;
}
