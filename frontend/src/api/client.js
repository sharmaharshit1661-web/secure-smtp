/**
 * Fetch wrapper for the Secure SMTP FastAPI backend.
 */

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000';

async function request(path, options = {}) {
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
    },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `API error: ${res.status}`);
  }
  return res.json();
}

export async function getHosts() {
  return request('/api/hosts');
}

export async function getHostDetail(hostId) {
  return request(`/api/hosts/${hostId}`);
}

export async function getSessionDetail(sessionId) {
  return request(`/api/sessions/${sessionId}`);
}

export async function getSessionExplanation(sessionId) {
  return request(`/api/sessions/${sessionId}/explain`);
}

export async function getAnalysisStatus(jobId) {
  return request(`/api/analyze/${jobId}/status`);
}

export async function uploadPcap(file) {
  const formData = new FormData();
  formData.append('file', file);
  const url = `${API_BASE}/api/analyze`;
  const res = await fetch(url, { method: 'POST', body: formData });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `Upload failed: ${res.status}`);
  }
  return res.json();
}

export function getReportUrl(jobId, format) {
  return `${API_BASE}/api/reports/${jobId}.${format}`;
}
