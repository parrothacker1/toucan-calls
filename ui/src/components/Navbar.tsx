import { Settings } from 'lucide-react'
import type { ConnectionState } from '../hooks/useWebSocket'
import StatusIndicator from './StatusIndicator'

interface NavbarProps {
  state: ConnectionState
  onSettingsToggle: () => void
}

export default function Navbar({ state, onSettingsToggle }: NavbarProps) {
  return (
    <nav className="navbar">
      <div className="navbar-brand">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/>
        </svg>
        Toucan Calls
      </div>
      <div className="navbar-center">
        <StatusIndicator state={state} />
      </div>
      <div className="navbar-actions">
        <button className="settings-btn" onClick={onSettingsToggle} aria-label="Settings">
          <Settings size={18} />
        </button>
      </div>
    </nav>
  )
}
