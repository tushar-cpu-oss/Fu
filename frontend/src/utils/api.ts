// Thin fetch wrapper around the FastAPI backend.
// The JWT is passed in explicitly by callers — it lives only in React state
// (see App.tsx), never in localStorage, per the auth design.
export const API_BASE_URL = (
  (import.meta as any).env?.VITE_API_BASE_URL ||
  'https://dff-al3w.onrender.com'
).replace(/\/+$/, '');

export interface AnalyzeResponse {
  session_id: string;
  language: string;
  risk_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  synthetic_probability: number;
  speaker_match_probability: number;
  risk_factors: string[];
  suggestion: string;
  scam_score: number;
  ai_voice_percent: number;
  threat_location?: { city: string; latitude: number; longitude: number };
}

function authHeaders(token?: string | null): HeadersInit {
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function handle<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || JSON.stringify(body);
    } catch {
      /* ignore non-JSON error bodies */
    }
    throw new Error(`API error ${res.status}: ${detail}`);
  }
  return res.json() as Promise<T>;
}


export interface GoogleAuthStatus {
  configured: boolean;
  client_configured: boolean;
  backend_configured: boolean;
  package_available: boolean;
}

export async function getGoogleAuthStatus(): Promise<GoogleAuthStatus> {
  const res = await fetch(`${API_BASE_URL}/api/v1/auth/google/status`);
  return handle<GoogleAuthStatus>(res);
}

export async function loginWithGoogle(credential: string): Promise<{ access_token: string }> {
  const res = await fetch(`${API_BASE_URL}/api/v1/auth/google`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential }),
  });
  return handle(res);
}

export async function registerWithEmail(name: string, email: string, password: string) {
  const res = await fetch(`${API_BASE_URL}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, email, password }),
  });
  return handle<{ user_id: string; name: string; email: string; role: string }>(res);
}

export async function loginWithEmail(email: string, password: string) {
  const res = await fetch(`${API_BASE_URL}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  return handle<{ access_token: string }>(res);
}

export interface MeResponse {
  user_id: string;
  name: string;
  email: string;
  role: string;
}

// The authoritative source for role — never trust a client-side "role"
// field (e.g. a job-title dropdown) for admin/demo-data gating.
export async function getMe(token: string): Promise<MeResponse> {
  const res = await fetch(`${API_BASE_URL}/api/v1/auth/me`, {
    headers: authHeaders(token),
  });
  return handle<MeResponse>(res);
}

export async function analyzeAudio(
  file: File,
  sessionId: string,
  language: string,
  token?: string | null,
  onUploadProgress?: (percent: number) => void
): Promise<AnalyzeResponse> {
  const form = new FormData();
  form.append('session_id', sessionId);
  form.append('language', language);
  form.append('file', file);

  if (!onUploadProgress) {
    const res = await fetch(`${API_BASE_URL}/api/v1/analyze/audio`, {
      method: 'POST',
      headers: authHeaders(token),
      body: form,
    });
    return handle<AnalyzeResponse>(res);
  }

  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open('POST', `${API_BASE_URL}/api/v1/analyze/audio`);
    if (token) request.setRequestHeader('Authorization', `Bearer ${token}`);
    request.upload.onprogress = (event) => {
      if (event.lengthComputable) onUploadProgress(Math.round((event.loaded / event.total) * 100));
    };
    request.onload = () => {
      try {
        const body = JSON.parse(request.responseText);
        if (request.status >= 200 && request.status < 300) resolve(body as AnalyzeResponse);
        else reject(new Error(`API error ${request.status}: ${body.detail || request.statusText}`));
      } catch {
        reject(new Error('The analysis service returned an invalid response.'));
      }
    };
    request.onerror = () => reject(new Error('Could not reach the analysis backend.'));
    request.send(form);
  });
}

export interface CallsHistoryResponse {
  analysis_results: Array<Record<string, any>>;
  call_sessions: Array<Record<string, any>>;
  demo_calls?: Array<Record<string, any>>;
  total_analysis_results?: number;
}

export async function getMyCalls(token: string): Promise<CallsHistoryResponse> {
  const res = await fetch(`${API_BASE_URL}/api/v1/calls`, {
    headers: authHeaders(token),
  });
  return handle<CallsHistoryResponse>(res);
}

export async function getCall(sessionId: string, token: string): Promise<Record<string, any>> {
  const res = await fetch(`${API_BASE_URL}/api/v1/calls/${encodeURIComponent(sessionId)}`, {
    headers: authHeaders(token),
  });
  return handle<Record<string, any>>(res);
}

export async function startCallSession(language: string, token: string) {
  const res = await fetch(`${API_BASE_URL}/api/v1/calls/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders(token) },
    body: JSON.stringify({ language }),
  });
  return handle(res);
}

export async function endCallSession(sessionId: string, token: string, result?: Record<string, any>) {
  const res = await fetch(`${API_BASE_URL}/api/v1/calls/${sessionId}/end`, {
    method: 'POST',
    headers: result ? { 'Content-Type': 'application/json', ...authHeaders(token) } : authHeaders(token),
    ...(result ? { body: JSON.stringify(result) } : {}),
  });
  return handle(res);
}
/**
 * Open the authenticated WebSocket used by the Live Analysis page.
 * HTTP(S) API URLs are converted to WS(S) automatically.
 */
export function createLiveAnalysisSocket(
  sessionId: string,
  language: string,
  token?: string | null,
): WebSocket {
  const wsBase = API_BASE_URL
    .replace(/^http:/, 'ws:')
    .replace(/^https:/, 'wss:');

  const params = new URLSearchParams({
    session_id: sessionId,
    language,
  });

  if (token) {
    params.set('token', token);
  }

  return new WebSocket(
    `${wsBase}/api/v1/analyze/live?${params.toString()}`
  );
}
