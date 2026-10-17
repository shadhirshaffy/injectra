import { lazy, Suspense } from 'react'
import './App.css'
const AuthApp = lazy(() => import('./AuthApp'))
export default function App() {
  const key = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY
  if (!key) return <main className="shell"><p className="eyebrow">INJECTRA</p><h1>Secure access starts here.</h1><p>Sign-in is not configured for this environment yet.</p></main>
  return <Suspense fallback={<main className="shell" role="status">Loading secure sign-in…</main>}><AuthApp publishableKey={key} /></Suspense>
}
