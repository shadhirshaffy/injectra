import { ClerkProvider, SignInButton, SignUpButton, UserButton, useAuth } from '@clerk/react'
import { useCallback, useEffect, useState } from 'react'
import type { FormEvent } from 'react'

type Organization = { id: string; name: string; role: 'owner' | 'admin' | 'developer' }
type Profile = { id: string; organizations: Organization[] }
type Member = { id: string; user_id: string; role: string }

function Workspace() {
  const { isLoaded, isSignedIn, getToken } = useAuth()
  const [profile, setProfile] = useState<Profile | null>(null)
  const [selection, setSelection] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [invitation, setInvitation] = useState('')
  const [members, setMembers] = useState<Member[]>([])
  const organization = profile?.organizations.find(item => item.id === selection)
  const canManage = organization?.role === 'owner' || organization?.role === 'admin'

  const api = useCallback(async <T,>(path: string, method = 'GET', body?: object, signal?: AbortSignal): Promise<T> => {
    const token = await getToken()
    if (!token) throw new Error('Please sign in again.')
    const response = await fetch(`${import.meta.env.VITE_API_BASE_URL ?? ''}/api/v1${path}`, {
      method, signal, credentials: 'omit', cache: 'no-store',
      headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    })
    if (!response.ok) {
      if (response.status === 401) throw new Error('Your session is no longer active. Please sign in again.')
      if (response.status === 403) throw new Error('Your account does not have permission for this action.')
      if (response.status === 409) throw new Error('This action conflicts with the current organization state.')
      if (response.status === 422) throw new Error('Check the information you entered and try again.')
      throw new Error('The request could not be completed. Please try again.')
    }
    return response.status === 204 ? undefined as T : response.json() as Promise<T>
  }, [getToken])

  const refresh = useCallback(async (signal?: AbortSignal) => {
    const next = await api<Profile>('/me', 'GET', undefined, signal)
    if (signal?.aborted) return
    setProfile(next)
    setSelection(previous => next.organizations.some(item => item.id === previous)
      ? previous : next.organizations[0]?.id ?? '')
  }, [api])

  useEffect(() => {
    if (!isSignedIn) return
    const controller = new AbortController()
    void api<Profile>('/me', 'GET', undefined, controller.signal).then(next => {
      if (controller.signal.aborted) return
      setProfile(next)
      setSelection(previous => next.organizations.some(item => item.id === previous)
        ? previous : next.organizations[0]?.id ?? '')
    }).catch(() => {
      if (!controller.signal.aborted) setMessage('We could not load your workspace. Please try again.')
    })
    return () => controller.abort()
  }, [isSignedIn, api])

  async function submit(event: FormEvent<HTMLFormElement>, action: (data: FormData) => Promise<void>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    setBusy(true)
    setMessage('')
    try { await action(data) }
    catch (error) { setMessage(error instanceof Error ? error.message : 'The action could not be completed.') }
    finally { setBusy(false) }
  }

  if (!isLoaded) return <main className="shell" role="status">Loading your session…</main>
  if (!isSignedIn) return <main className="shell">
    <p className="eyebrow">INJECTRA · AI SECURITY</p><h1>Your security workspace.</h1>
    <p>Sign in to manage your organizations, applications, and security policies.</p>
    <div className="actions"><SignInButton mode="modal"><button>Sign in</button></SignInButton>
      <SignUpButton mode="modal"><button className="secondary">Create account</button></SignUpButton></div>
  </main>

  return <main className="shell">
    <header><div><p className="eyebrow">INJECTRA</p><h1>Organization access</h1></div><UserButton /></header>
    <p role="status" aria-live="polite">{message}</p>
    {!profile ? <button onClick={() => void refresh().catch(() => setMessage('Unable to load your workspace.'))}>Retry loading workspace</button> : <>
      {profile.organizations.length > 0 && <section>
        <label htmlFor="organization">Current organization</label>
        <select id="organization" value={selection} disabled={busy} onChange={event => {
          setSelection(event.target.value); setInvitation(''); setMembers([])
        }}>{profile.organizations.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select>
        <p>Your role: <strong>{organization?.role}</strong></p>
        <button className="secondary" disabled={busy} onClick={() => {
          setBusy(true)
          void api<{ items: Member[] }>(`/organizations/${selection}/memberships`)
            .then(result => setMembers(result.items)).catch(error => setMessage(error.message))
            .finally(() => setBusy(false))
        }}>View members</button>
        {members.length > 0 && <ul>{members.map(member => <li key={member.id}>
          {member.user_id === profile.id ? 'You' : `Member ${member.user_id.slice(0, 8)}`} · {member.role}
        </li>)}</ul>}
      </section>}
      <div className="grid">
        <section><h2>Create an organization</h2><p>You become the owner of your new organization.</p>
          <form onSubmit={event => void submit(event, async data => {
            await api('/organizations', 'POST', { name: data.get('name') }); await refresh()
            setMessage('Organization created.')
          })}><label htmlFor="name">Organization name</label><input id="name" name="name" required maxLength={150} />
            <button disabled={busy}>Create organization</button></form></section>
        <section><h2>Accept an invitation</h2><p>Use the invitation code from your organization administrator.</p>
          <form onSubmit={event => void submit(event, async data => {
            await api('/invitations/accept', 'POST', { token: data.get('token') }); await refresh()
            setMessage('Invitation accepted.')
          })}><label htmlFor="token">Invitation code</label><input id="token" name="token" required autoComplete="off" minLength={43} maxLength={43} />
            <button disabled={busy}>Join organization</button></form></section>
        {canManage && <section><h2>Invite a teammate</h2>
          <form onSubmit={event => void submit(event, async data => {
            const result = await api<{ token: string }>(`/organizations/${selection}/invitations`, 'POST', {
              email: data.get('email'), role: data.get('role'),
            })
            setInvitation(result.token); setMessage('Invitation created. Share the code privately with your teammate.')
          })}><label htmlFor="email">Teammate email</label><input id="email" name="email" required type="email" />
            <label htmlFor="role">Role</label><select id="role" name="role"><option value="developer">Developer — read access</option>
              <option value="admin">Admin — management access</option></select><button disabled={busy}>Create invitation</button></form>
          {invitation && <div><label htmlFor="invitation">Invitation code — shown once</label>
            <input id="invitation" readOnly value={invitation} autoComplete="off" />
            <button className="secondary" onClick={() => setInvitation('')}>Hide code</button></div>}
        </section>}
      </div>
    </>}
  </main>
}

export default function AuthApp({ publishableKey }: { publishableKey: string }) {
  return <ClerkProvider publishableKey={publishableKey}><SessionWorkspace /></ClerkProvider>
}

function SessionWorkspace() {
  const { userId } = useAuth()
  return <Workspace key={userId ?? 'signed-out'} />
}
