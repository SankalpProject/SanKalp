import type { HttpClient } from '../../../core/http/HttpClient';

export interface HomeGreeting {
  message: string;
}

export interface HomeRepository {
  getGreeting(): Promise<HomeGreeting>;
}

/** Uses the authorized client: the bearer token is attached and refreshed automatically. */
export class HttpHomeRepository implements HomeRepository {
  constructor(private readonly http: HttpClient) {}

  getGreeting() {
    return this.http.request<HomeGreeting>({ method: 'GET', path: '/api/v1/home' });
  }
}
