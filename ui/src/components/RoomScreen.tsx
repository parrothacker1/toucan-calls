import { useState } from 'react'
import { Plus, LogIn, Copy, Mic, Users } from 'lucide-react'
import type { ConnectionState } from '../hooks/useWebSocket'

interface RoomScreenProps {
  state: ConnectionState
  roomId: string | null
  isSpeech: boolean
  speakers: string[]
  onCreateRoom: () => void
  onJoinRoom: (roomId: string) => void
}

export default function RoomScreen({
  state,
  roomId,
  isSpeech,
  speakers,
  onCreateRoom,
  onJoinRoom,
}: RoomScreenProps) {
  const [joinId, setJoinId] = useState('')
  const [showJoin, setShowJoin] = useState(false)
  const [copied, setCopied] = useState(false)

  const copyRoomId = () => {
    if (roomId) {
      navigator.clipboard.writeText(roomId)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  // Room selection screen
  if (state === 'authenticated') {
    return (
      <div className="card fade-in" style={{ maxWidth: 480 }}>
        <h2 className="card-title">Join a Room</h2>
        <p className="card-subtitle">Create a new room or join an existing one</p>

        <div className="room-choice">
          <div className="room-choice-option" onClick={onCreateRoom}>
            <div className="room-choice-icon">
              <Plus size={22} />
            </div>
            <div className="room-choice-text">
              <h3>Create Room</h3>
              <p>Start a new voice channel</p>
            </div>
          </div>

          <div className="divider">or</div>

          {!showJoin ? (
            <div className="room-choice-option" onClick={() => setShowJoin(true)}>
              <div className="room-choice-icon">
                <LogIn size={22} />
              </div>
              <div className="room-choice-text">
                <h3>Join Room</h3>
                <p>Enter a room ID to join</p>
              </div>
            </div>
          ) : (
            <form
              onSubmit={(e) => {
                e.preventDefault()
                if (joinId.trim()) onJoinRoom(joinId.trim())
              }}
            >
              <div className="form-group">
                <label className="form-label">Room ID</label>
                <input
                  type="text"
                  className="form-input"
                  value={joinId}
                  onChange={(e) => setJoinId(e.target.value)}
                  placeholder="Paste room UUID"
                  autoFocus
                />
              </div>
              <div className="btn-group">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setShowJoin(false)}
                >
                  Back
                </button>
                <button
                  type="submit"
                  className="btn btn-teal"
                  disabled={!joinId.trim()}
                >
                  Join
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    )
  }

  // In-room view
  return (
    <div className="room-container fade-in">
      <div className="room-header">
        <h2 className="card-title">Voice Room</h2>
        {roomId && (
          <div className="room-id" onClick={copyRoomId} title="Click to copy">
            <Copy size={14} />
            {roomId.slice(0, 8)}...{roomId.slice(-4)}
          </div>
        )}
      </div>

      {/* VAD Indicator */}
      <div className="vad-indicator">
        <div className={`vad-dot ${isSpeech ? 'active' : ''}`} />
        <span className={`vad-label ${isSpeech ? 'active' : ''}`}>
          <Mic size={14} style={{ marginRight: 6, verticalAlign: 'middle' }} />
          {isSpeech ? 'Speech Detected' : 'Silence'}
        </span>
      </div>

      {/* Speakers */}
      <div className="speaker-section">
        <div className="speaker-section-title">
          <Users size={14} style={{ marginRight: 6, verticalAlign: 'middle' }} />
          Active Speakers
        </div>
        <div className="speaker-list">
          {speakers.length > 0 ? (
            speakers.map((speaker, i) => (
              <div key={`${speaker}-${i}`} className="speaker-item">
                <div className="speaker-avatar">
                  {speaker.charAt(0).toUpperCase()}
                </div>
                <span className="speaker-name">{speaker}</span>
              </div>
            ))
          ) : (
            <div className="speaker-empty">
              Waiting for speakers...
            </div>
          )}
        </div>
      </div>

      {copied && <div className="copied-toast">Room ID copied!</div>}
    </div>
  )
}
