const BASE = import.meta.env.VITE_API_URL || 'http://localhost:5000/api'
export async function api(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, options)
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`)
  return data
}
