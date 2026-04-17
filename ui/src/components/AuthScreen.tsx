import { useState } from 'react'
import { LogIn, AlertCircle } from 'lucide-react'
import type { ConnectionState } from '../hooks/useWebSocket'

interface AuthScreenProps {
  state: ConnectionState
  error: string | null
  onConnect: () => void
  onAuth: (username: string, password: string) => void
}

export default function AuthScreen({ state, error, onConnect, onAuth }: AuthScreenProps) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  const isConnecting = state === 'connecting' || state === 'handshaking'
  const isAuthenticating = state === 'authenticating'
  const isConnected = state === 'connected' || state === 'authenticating'

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (state === 'disconnected') {
      onConnect()
    } else if (isConnected && username && password) {
      onAuth(username, password)
    }
  }

  return (
    <div className="card fade-in">
      <h2 className="card-title">Welcome</h2>
      <p className="card-subtitle">Connect to the Toucan server and authenticate</p>

      {error && (
        <div className="error-msg">
          <AlertCircle size={16} />
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit}>
        {state === 'disconnected' && (
          <button type="submit" className="btn btn-primary" disabled={isConnecting}>
            <LogIn size={16} />
            Connect to Server
          </button>
        )}

        {isConnecting && (
          <button type="button" className="btn btn-secondary" disabled>
            {state === 'connecting' ? 'Connecting...' : 'Handshaking...'}
          </button>
        )}

        {isConnected && (
          <>
            <div className="form-group">
              <label className="form-label">Username</label>
              <input
                type="text"
                className="form-input"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username"
                autoFocus
                disabled={isAuthenticating}
              />
            </div>
            <div className="form-group">
              <label className="form-label">Password</label>
              <input
                type="password"
                className="form-input"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                disabled={isAuthenticating}
              />
            </div>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={!username || !password || isAuthenticating}
            >
              <LogIn size={16} />
              {isAuthenticating ? 'Authenticating...' : 'Log In'}
            </button>
          </>
        )}
      </form>
    </div>
  )
}
