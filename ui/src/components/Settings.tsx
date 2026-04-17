import { X, Power } from 'lucide-react'

interface SettingsProps {
  open: boolean
  model: string
  onClose: () => void
  onSwitchModel: (model: string) => void
  onShutdown: () => void
}

export default function Settings({ open, model, onClose, onSwitchModel, onShutdown }: SettingsProps) {
  return (
    <div className={`settings-panel ${open ? 'open' : ''}`}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <h3 className="settings-title" style={{ margin: 0 }}>Settings</h3>
        <button className="settings-btn" onClick={onClose} aria-label="Close settings">
          <X size={18} />
        </button>
      </div>

      <div className="settings-group">
        <div className="settings-label">Audio Model</div>
        <div className="model-toggle">
          <button
            className={`model-option ${model === 'vad' ? 'active' : ''}`}
            onClick={() => onSwitchModel('vad')}
          >
            VAD
          </button>
          <button
            className={`model-option ${model === 'ml' ? 'active' : ''}`}
            onClick={() => onSwitchModel('ml')}
          >
            ML Diarization
          </button>
        </div>
        <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 8 }}>
          {model === 'vad'
            ? 'Voice Activity Detection — detects speech vs silence'
            : 'Speaker Diarization — identifies individual speakers'}
        </p>
      </div>

      <div className="settings-group" style={{ marginTop: 'auto', paddingTop: 24 }}>
        <button className="btn btn-danger" onClick={onShutdown}>
          <Power size={16} />
          Shutdown Client
        </button>
      </div>
    </div>
  )
}
