package netx

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"testing"
	"time"

	pkgerr "github.com/pkg/errors" // 引入 pkg/errors 来模拟错误包装
	"github.com/threatexpert/gonc/v2/misc"
)

func TestUDP1toN(t *testing.T) {
	// 1. 预先创建一个共享的 net.UDPConn 并绑定地址
	localUDPAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:8000")
	if err != nil {
		log.Fatalf("Failed to resolve local UDP addr: %v", err)
	}
	sharedUDPConn, err := net.ListenUDP("udp", localUDPAddr)
	if err != nil {
		log.Fatalf("Failed to listen on shared UDPConn: %v", err)
	}
	log.Printf("Shared UDPConn listening on %s", sharedUDPConn.LocalAddr().String())

	logToStderr := misc.NewLog(os.Stderr, "[UDPSession] ", log.LstdFlags|log.Lmsgprefix|log.Lshortfile)
	// 2. 使用这个共享的 UDPConn 初始化你的 UDPSessionDialer
	dialer, err := NewUDPSessionDialer(sharedUDPConn, false, 1500, logToStderr)
	if err != nil {
		log.Fatalf("Failed to create custom dialer: %v", err)
	}
	defer dialer.Close() // 确保在 main 函数退出时关闭 dialer

	// 模拟远程服务器的回复逻辑
	go func() {
		serverBuf := make([]byte, 1500)
		for {
			// 设置一个短的 ReadDeadline，以便在 dialer.Close() 时能退出循环
			sharedUDPConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, clientAddr, err := sharedUDPConn.ReadFromUDP(serverBuf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // 超时是正常情况，继续循环
				}
				if err.Error() == "use of closed network connection" {
					log.Printf("Server: Underlying UDP connection closed, stopping server read loop.")
					return
				}
				log.Printf("Server: Error reading from sharedUDPConn: %v", err)
				return
			}

			receivedMsg := string(serverBuf[:n])
			log.Printf("Server received '%s' from %s", receivedMsg, clientAddr.String())

			// 模拟延迟回复，让客户端有可能超时
			time.Sleep(500 * time.Millisecond) // 模拟一个比较长的网络延迟

			replyMsg := fmt.Sprintf("Server reply to '%s'", receivedMsg)
			_, err = sharedUDPConn.WriteToUDP([]byte(replyMsg), clientAddr)
			if err != nil {
				log.Printf("Server error replying to %s: %v", clientAddr.String(), err)
			} else {
				log.Printf("Server replied '%s' to %s", replyMsg, clientAddr.String())
			}
		}
	}()

	// --- 测试 SetReadDeadline ---
	fmt.Println("\n--- Testing SetReadDeadline ---")
	remoteAddrReadTest, _ := net.ResolveUDPAddr("udp", "127.0.0.1:5302")
	connReadTest, err := dialer.DialUDP("udp", remoteAddrReadTest)
	if err != nil {
		log.Fatalf("Read Test: Failed to dial: %v", err)
	}
	defer connReadTest.Close()

	// 设置一个很短的读超时
	readTimeout := time.Now().Add(200 * time.Millisecond)
	connReadTest.SetReadDeadline(readTimeout)
	log.Printf("Read Test: Set read deadline for %s to %v", connReadTest.RemoteAddr().String(), readTimeout)

	// 立即尝试读取，应该会超时，因为服务器有延迟
	bufRead := make([]byte, 1500)
	n, err := connReadTest.Read(bufRead)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Printf("Read Test: Successfully hit read timeout as expected: %v", err)
		} else {
			log.Printf("Read Test: Unexpected read error: %v", err)
		}
	} else {
		log.Printf("Read Test: Unexpectedly received data: '%s'", string(bufRead[:n]))
	}

	// 重新设置一个较长的读超时，并发送数据，期望收到回复
	connReadTest.SetReadDeadline(time.Now().Add(2 * time.Second))
	msg := "Ping for Read Test"
	_, err = connReadTest.Write([]byte(msg))
	if err != nil {
		log.Printf("Read Test: Write error: %v", err)
	} else {
		log.Printf("Read Test: Sent '%s'", msg)
	}
	n, err = connReadTest.Read(bufRead)
	if err != nil {
		log.Printf("Read Test: Error reading after re-setting deadline: %v", err)
	} else {
		log.Printf("Read Test: Received after re-setting deadline: '%s'", string(bufRead[:n]))
	}

	// --- 测试 SetWriteDeadline ---
	fmt.Println("\n--- Testing SetWriteDeadline ---")
	remoteAddrWriteTest, _ := net.ResolveUDPAddr("udp", "127.0.0.1:5303")
	connWriteTest, err := dialer.DialUDP("udp", remoteAddrWriteTest)
	if err != nil {
		log.Fatalf("Write Test: Failed to dial: %v", err)
	}
	defer connWriteTest.Close()

	// 模拟 writeCh 满的情况 (通常 UDP 不会满，但这里为了测试写超时逻辑)
	// 我们可以通过一个极小的 readCh 缓冲区来模拟 writeLoop 被阻塞，从而导致 writeCh 无法清空
	// 但这在实际 UDP 中不常见，因为 WriteToUDP 通常是非阻塞的。
	// 这里更直接的测试是设置一个已经过去的 Deadline。
	writeTimeout := time.Now().Add(-1 * time.Second) // 立即超时
	connWriteTest.SetWriteDeadline(writeTimeout)
	log.Printf("Write Test: Set write deadline for %s to %v (already past)", connWriteTest.RemoteAddr().String(), writeTimeout)

	msgWrite := "This should timeout immediately"
	_, err = connWriteTest.Write([]byte(msgWrite))
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Printf("Write Test: Successfully hit write timeout as expected: %v", err)
		} else {
			log.Printf("Write Test: Unexpected write error: %v", err)
		}
	} else {
		log.Printf("Write Test: Unexpectedly sent data: '%s'", msgWrite)
	}

	// 重新设置一个正常的写超时
	connWriteTest.SetWriteDeadline(time.Now().Add(5 * time.Second))
	msgWriteOk := "This should send fine"
	_, err = connWriteTest.Write([]byte(msgWriteOk))
	if err != nil {
		log.Printf("Write Test: Error writing after re-setting deadline: %v", err)
	} else {
		log.Printf("Write Test: Successfully sent: '%s'", msgWriteOk)
	}

	// --- 测试 SetDeadline (同时设置读写) ---
	fmt.Println("\n--- Testing SetDeadline ---")
	remoteAddrBothTest, _ := net.ResolveUDPAddr("udp", "127.0.0.1:5304")
	connBothTest, err := dialer.DialUDP("udp", remoteAddrBothTest)
	if err != nil {
		log.Fatalf("Both Test: Failed to dial: %v", err)
	}
	defer connBothTest.Close()

	combinedDeadline := time.Now().Add(500 * time.Millisecond)
	connBothTest.SetDeadline(combinedDeadline)
	log.Printf("Both Test: Set combined deadline to %v", combinedDeadline)

	// 尝试读取，应该会超时
	bufBoth := make([]byte, 1500)
	n, err = connBothTest.Read(bufBoth)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Printf("Both Test: Successfully hit read timeout (from SetDeadline) as expected: %v", err)
		} else {
			log.Printf("Both Test: Unexpected read error: %v", err)
		}
	} else {
		log.Printf("Both Test: Unexpectedly received data: '%s'", string(bufBoth[:n]))
	}

	// 尝试写入，应该也会超时 (因为我们没有及时清空 writeCh，这里为了演示，假设会超时)
	// 在实际 UDP 中，WriteToUDP 通常不会阻塞到超时，除非底层缓冲区满了。
	// 但在我们的模拟 Conn 中，如果 writeCh 满且没有及时被 writeLoop 清空，则会超时。
	msgBoth := "Message for combined deadline"
	_, err = connBothTest.Write([]byte(msgBoth))
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Printf("Both Test: Successfully hit write timeout (from SetDeadline) as expected: %v", err)
		} else {
			log.Printf("Both Test: Unexpected write error: %v", err)
		}
	} else {
		log.Printf("Both Test: Unexpectedly sent data: '%s'", msgBoth)
	}

	time.Sleep(2 * time.Second) // 等待日志输出完成
	fmt.Println("\n--- All Deadline Tests Complete ---")
}

// TestIsTimeout 是 isTimeout 函数的单元测试函数
func TestIsTimeout(t *testing.T) {

	// --- 模拟各种错误场景的辅助函数 ---
	// 1. 标准库 net.OpError 超时
	getStandardTimeoutError := func() error {
		return &net.OpError{
			Op:  "dial",
			Net: "tcp",
			Err: os.ErrDeadlineExceeded, // 关键的超时错误
		}
	}
	// 2. 被包装过的标准库超时错误
	getWrappedStandardTimeoutError := func() error {
		return pkgerr.Wrap(getStandardTimeoutError(), "failed to connect to server")
	}
	// 3. KCP 的超时错误
	getKcpTimeoutError := func() error {
		return newTimeoutError("test-timeout-error", true)
	}
	// 4. 被包装过的 KCP 超时错误 (你遇到的原始情况)
	getWrappedKcpTimeoutError := func() error {
		return pkgerr.WithStack(newTimeoutError("test-timeout-error", true))
	}
	// 5. 一个非超时的普通错误
	getNonTimeoutError := func() error {
		return errors.New("a generic error")
	}

	// 定义测试用例的结构体
	testCases := []struct {
		name string // 测试用例的名称
		err  error  // 输入的错误
		want bool   // 期望的结果 (true 表示是超时)
	}{
		{
			name: "Standard net.Error Timeout",
			err:  getStandardTimeoutError(),
			want: true,
		},
		{
			name: "Wrapped standard net.Error Timeout",
			err:  getWrappedStandardTimeoutError(),
			want: true,
		},
		{
			name: "KCP Timeout Error",
			err:  getKcpTimeoutError(),
			want: true,
		},
		{
			name: "Wrapped KCP Timeout Error",
			err:  getWrappedKcpTimeoutError(),
			want: true,
		},
		{
			name: "Non-timeout generic error",
			err:  getNonTimeoutError(),
			want: false,
		},
		{
			name: "Nil error",
			err:  nil,
			want: false,
		},
	}

	// 遍历所有测试用例
	for _, tc := range testCases {
		// t.Run 会创建一个子测试，方便定位问题
		t.Run(tc.name, func(t *testing.T) {
			// 执行被测试的函数
			got := isTimeout(tc.err)

			// 断言：检查实际结果是否与期望结果相符
			if got != tc.want {
				// 如果不符，测试失败，并打印错误信息
				t.Errorf("isTimeout() = %v, want %v", got, tc.want)
			}
		})
	}
}
