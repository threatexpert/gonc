package netx

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
)

// BufferedConn 包装 net.Conn 和 bufio.Reader
// 使得我们可以先 Peek，然后再像普通 net.Conn 一样读取
type BufferedConn struct {
	net.Conn
	Reader *bufio.Reader
}

// Read 重写 Read 方法，优先从 bufio.Reader 中读取
func (c *BufferedConn) Read(p []byte) (n int, err error) {
	return c.Reader.Read(p)
}

func (c *BufferedConn) CloseWrite() error {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return errors.New("CloseWrite not supported")
}

// NewBufferedConn 创建一个新的带缓冲连接
func NewBufferedConn(c net.Conn) *BufferedConn {
	return &BufferedConn{
		Conn:   c,
		Reader: bufio.NewReader(c),
	}
}

// discardAndUnwrap 返回原始的 net.Conn，但会先处理掉缓冲区里剩余的数据
// 注意：一旦调用这个，bufConn 就不能再用了
func (bc *BufferedConn) DiscardAndUnwrap() net.Conn {
	// 检查缓冲区里还有多少没读的数据
	buffered := bc.Reader.Buffered()
	if buffered > 0 {
		// 如果有剩余数据，我们需要把这些数据和原始 conn 组合起来
		// 创建一个 MultiReader：先读剩余的字节，读完后再读 conn
		leftover, _ := bc.Reader.Peek(buffered) // 拿出剩余数据
		// 注意：这里需要把 leftover 复制一份，因为 buffer 可能会被重用或回收
		leftoverCopy := make([]byte, len(leftover))
		copy(leftoverCopy, leftover)

		// 返回一个新的组合连接
		return &PrefixConn{
			Conn:   bc.Conn,
			reader: io.MultiReader(bytes.NewReader(leftoverCopy), bc.Conn),
		}
	}

	// 如果缓冲区是空的，直接返回原始连接
	return bc.Conn
}

// PrefixConn 包装 net.Conn，但在读取时先读前缀数据
type PrefixConn struct {
	net.Conn
	reader io.Reader
}

func (c *PrefixConn) Read(p []byte) (n int, err error) {
	return c.reader.Read(p)
}

func ReadString(conn io.Reader, delim byte, maxLen int) (string, error) {
	var buf []byte
	tmp := make([]byte, 1)

	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[0])

			// --- 新增：检查长度限制 ---
			if len(buf) > maxLen {
				return "", fmt.Errorf("string too long: exceeded maxLen=%d", maxLen)
			}

			if tmp[0] == delim {
				return string(buf), nil
			}
		}

		if err != nil {
			if errors.Is(err, io.EOF) && len(buf) > 0 {
				return string(buf), nil
			}
			return "", err
		}
	}
}
