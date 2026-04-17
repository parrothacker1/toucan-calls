import { useCallback, useEffect, useRef, useState } from 'react'

export type ConnectionState =
  | 'disconnected'
  | 'connecting'
  | 'handshaking'
  | 'connected'
  | 'authenticating'
  | 'authenticated'
  | 'in_room'

export interface WSEvent {
  type: string
  state?: ConnectionState
  roomId?: string
  isSpeech?: boolean
  speakers?: string[]
  model?: string
  message?: string
}

interface UseWebSocketReturn {
  state: ConnectionState
  roomId: string | null
  isSpeech: boolean
  speakers: string[]
  model: string
  error: string | null
  connect: () => void
  authenticate: (username: string, password: string) => void
  createRoom: () => void
  joinRoom: (roomId: string) => void
  switchModel: (model: string) => void
  shutdown: () => void
  wsReady: boolean
}

export function useWebSocket(): UseWebSocketReturn {
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const [state, setState] = useState<ConnectionState>('disconnected')
  const [roomId, setRoomId] = useState<string | null>(null)
  const [isSpeech, setIsSpeech] = useState(false)
  const [speakers, setSpeakers] = useState<string[]>([])
  const [model, setModel] = useState('vad')
  const [error, setError] = useState<string | null>(null)
  const [wsReady, setWsReady] = useState(false)

  const connectWS = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws`)

    ws.onopen = () => {
      wsRef.current = ws
      setWsReady(true)
      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current)
        reconnectTimer.current = null
      }
    }

    ws.onmessage = (event) => {
      const msg: WSEvent = JSON.parse(event.data)

      switch (msg.type) {
        case 'STATUS':
          if (msg.state) setState(msg.state)
          if (msg.model) setModel(msg.model)
          if (msg.state === 'disconnected') {
            setRoomId(null)
            setIsSpeech(false)
            setSpeakers([])
          }
          break
        case 'ROOM_JOINED':
          if (msg.roomId) setRoomId(msg.roomId)
          setError(null)
          break
        case 'VAD_RESULT':
          setIsSpeech(msg.isSpeech ?? false)
          break
        case 'SPEAKER_DETECTED':
          if (msg.speakers) setSpeakers(msg.speakers)
          break
        case 'MODEL_CHANGED':
          if (msg.model) setModel(msg.model)
          break
        case 'ERROR':
          setError(msg.message ?? 'Unknown error')
          // Auto-clear error after 5 seconds
          setTimeout(() => setError(null), 5000)
          break
      }
    }

    ws.onclose = () => {
      setWsReady(false)
      wsRef.current = null
      // Auto-reconnect after 1 second
      reconnectTimer.current = setTimeout(() => {
        connectWS()
      }, 1000)
    }

    ws.onerror = () => {
      // onclose will fire after this, which handles reconnect
    }
  }, [])

  useEffect(() => {
    connectWS()
    return () => {
      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current)
      }
      wsRef.current?.close()
    }
  }, [connectWS])

  const send = useCallback((msg: Record<string, unknown>) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(msg))
    }
  }, [])

  const connect = useCallback(() => {
    setError(null)
    send({ type: 'CONNECT' })
  }, [send])

  const authenticate = useCallback((username: string, password: string) => {
    setError(null)
    send({ type: 'AUTH', username, password })
  }, [send])

  const createRoom = useCallback(() => {
    send({ type: 'CREATE_ROOM' })
  }, [send])

  const joinRoom = useCallback((id: string) => {
    send({ type: 'JOIN_ROOM', roomId: id })
  }, [send])

  const switchModel = useCallback((m: string) => {
    send({ type: 'SWITCH_MODEL', model: m })
  }, [send])

  const shutdown = useCallback(() => {
    send({ type: 'SHUTDOWN' })
  }, [send])

  return {
    state,
    roomId,
    isSpeech,
    speakers,
    model,
    error,
    connect,
    authenticate,
    createRoom,
    joinRoom,
    switchModel,
    shutdown,
    wsReady,
  }
}
