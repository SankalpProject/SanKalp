/** Error returned by the API (RFC 7807 problem details with a stable `code`). */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly retryAfterSeconds?: number,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

/** The request never reached the server or timed out. */
export class NetworkError extends Error {
  constructor(message = 'Network unavailable. Check your connection and try again.') {
    super(message);
    this.name = 'NetworkError';
  }
}
