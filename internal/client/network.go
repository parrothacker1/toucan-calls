package client

import (
	"fmt"

	"github.com/ishidawataru/sctp"
	"github.com/toucan/toucan-calls/internal/utils/codec"
	"github.com/toucan/toucan-calls/internal/utils/encrypt"
	"github.com/toucan/toucan-calls/internal/utils/values"
)

func (c *Client) connect() error {
	addr, err := sctp.ResolveSCTPAddr(
		"sctp",
		fmt.Sprintf("%s:%s", c.Host, c.Port),
	)
	if err != nil {
		return err
	}
	conn, err := sctp.DialSCTP("sctp", nil, addr)
	if err != nil {
		return err
	}
	c.Conn = conn
	c.Log.WithField("remote", conn.RemoteAddr().String()).Info("connected to server")
	return nil
}

func (c *Client) readLoop() {
	for {
		buf := make([]byte, 1024*100)
		n, err := c.Conn.Read(buf)
		if err != nil {
			return
		}
		dec, _ := encrypt.DecryptAES(buf[:n], c.AESKey)
		data, _, _ := codec.FECEncoder.DecodeData(dec)
		count := values.ClientchannelCount *
			values.ClientframesPerBuffer *
			values.ClientRate / 1000
		audio := make([]int16, count)
		codec.OpusDecoder.Decode(data, audio)
		select {
		case c.playbackBuf <- audio:
		default:
		}
	}
}
