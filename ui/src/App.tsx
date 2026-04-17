import { useState } from 'react'
import { useWebSocket } from './hooks/useWebSocket'
import Navbar from './components/Navbar'
import AuthScreen from './components/AuthScreen'
import RoomScreen from './components/RoomScreen'
import Settings from './components/Settings'

export default function App() {
  const [settingsOpen, setSettingsOpen] = useState(false)
  const ws = useWebSocket()

  const showAuth =
    ws.state === 'disconnected' ||
    ws.state === 'connecting' ||
    ws.state === 'handshaking' ||
    ws.state === 'connected' ||
    ws.state === 'authenticating'

  const showRoom = ws.state === 'authenticated' || ws.state === 'in_room'

  return (
    <>
      <Navbar
        state={ws.state}
        onSettingsToggle={() => setSettingsOpen((o) => !o)}
      />
      <main className="main">
        {!ws.wsReady ? (
          <div className="card fade-in">
            <h2 className="card-title">Connecting to UI server...</h2>
            <p className="card-subtitle">Establishing WebSocket connection</p>
          </div>
        ) : showAuth ? (
          <AuthScreen
            state={ws.state}
            error={ws.error}
            onConnect={ws.connect}
            onAuth={ws.authenticate}
          />
        ) : showRoom ? (
          <RoomScreen
            state={ws.state}
            roomId={ws.roomId}
            isSpeech={ws.isSpeech}
            speakers={ws.speakers}
            onCreateRoom={ws.createRoom}
            onJoinRoom={ws.joinRoom}
          />
        ) : null}
      </main>
      <Settings
        open={settingsOpen}
        model={ws.model}
        onClose={() => setSettingsOpen(false)}
        onSwitchModel={ws.switchModel}
        onShutdown={ws.shutdown}
      />
    </>
  )
}
