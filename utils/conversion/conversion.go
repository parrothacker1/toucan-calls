package conversion


import (
	"github.com/toucan/toucan-calls/utils/values"
)

func AddChunk(thisChunk values.AudioChunk,thisRoom values.Room) {
  thisRoom.AudioBuf.Mu.Lock()
  defer thisRoom.AudioBuf.Mu.Unlock()
  thisRoom.AudioBuf.Buffer = append(thisRoom.AudioBuf.Buffer, &thisChunk)
}
