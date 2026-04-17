import type { ConnectionState } from '../hooks/useWebSocket'

const labels: Record<ConnectionState, string> = {
  disconnected: 'Disconnected',
  connecting: 'Connecting',
  handshaking: 'Handshaking',
  connected: 'Connected',
  authenticating: 'Authenticating',
  authenticated: 'Authenticated',
  in_room: 'In Room',
}

function dotClass(state: ConnectionState): string {
  if (state === 'in_room') return 'status-dot in_room'
  if (state === 'disconnected') return 'status-dot disconnected'
  if (state === 'connecting' || state === 'handshaking' || state === 'authenticating')
    return 'status-dot connecting'
  return 'status-dot connected'
}

export default function StatusIndicator({ state }: { state: ConnectionState }) {
  return (
    <div className="status-badge">
      <span className={dotClass(state)} />
      {labels[state]}
    </div>
  )
}
