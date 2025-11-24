package netx

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// helper: 创建一个本地 UDP Echo Server 和一个连接到它的 Client Conn
// 返回:
// server: 模拟外部的对端 (Server)
// clientConn: 模拟用来做 Forwarder 的连接 (C)
func createUDPComponent(t *testing.T) (*net.UDPConn, *net.UDPConn) {
	// 1. 创建 Server 监听
	s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}

	// 2. 创建 Client 连接到 Server
	c, err := net.DialUDP("udp4", nil, s.LocalAddr().(*net.UDPAddr))
	if err != nil {
		s.Close()
		t.Fatalf("DialUDP failed: %v", err)
	}

	return s, c
}

// 基础流程测试: B <-> A <-> C <-> ExternalServer
func TestBridgeConn_BasicFlow(t *testing.T) {
	// 1. 创建 Bridge
	bc, err := NewBridge()
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}
	defer bc.Close()

	// 2. 创建外部组件
	server, cConn := createUDPComponent(t)
	defer server.Close()
	// cConn 将移交给 bridge 管理，bridge 会负责关闭它，但为了保险在测试结束尝试关闭
	defer cConn.Close()

	// 3. 设置 Forwarder
	bc.SetForwarder(cConn)

	// --- 测试 1: 从内部 (B) 发送数据到 外部 (Server) ---
	sendMsg := []byte("Hello from Internal")
	_, err = bc.B.Write(sendMsg)
	if err != nil {
		t.Fatalf("Write to B failed: %v", err)
	}

	// 外部 Server 读取
	buf := make([]byte, 1024)
	server.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, addr, err := server.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("Server Read failed: %v", err)
	}

	if !bytes.Equal(buf[:n], sendMsg) {
		t.Errorf("Server received wrong data. Want %s, Got %s", sendMsg, buf[:n])
	}
	// 验证源地址是否正确 (应该是 cConn 的本地地址)
	if addr.Port != cConn.LocalAddr().(*net.UDPAddr).Port {
		t.Errorf("Server received from wrong port")
	}

	// --- 测试 2: 从 外部 (Server) 回复数据到 内部 (B) ---
	replyMsg := []byte("Reply from Server")
	_, err = server.WriteToUDP(replyMsg, addr)
	if err != nil {
		t.Fatalf("Server Write failed: %v", err)
	}

	// 内部 B 读取
	bc.B.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err = bc.B.Read(buf)
	if err != nil {
		t.Fatalf("B Read failed: %v", err)
	}
	if !bytes.Equal(buf[:n], replyMsg) {
		t.Errorf("B received wrong data. Want %s, Got %s", replyMsg, buf[:n])
	}
}

// 轮转测试: 验证 SetForwarder 能平滑切换且清理旧资源
func TestBridgeConn_Rotation(t *testing.T) {
	bc, err := NewBridge()
	if err != nil {
		t.Fatal(err)
	}
	defer bc.Close()

	// --- 阶段 1: 使用 C1 ---
	s1, c1 := createUDPComponent(t)
	defer s1.Close()

	t.Logf("Set Forwarder to C1: %v", c1.LocalAddr())
	bc.SetForwarder(c1)

	// 验证 C1 通畅
	bc.B.Write([]byte("msg1"))
	buf := make([]byte, 1024)
	s1.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, _, err := s1.ReadFromUDP(buf); err != nil {
		t.Fatalf("C1 communication failed: %v", err)
	}

	// --- 阶段 2: 切换到 C2 ---
	s2, c2 := createUDPComponent(t)
	defer s2.Close()

	t.Logf("Rotating Forwarder to C2: %v", c2.LocalAddr())

	// 执行切换!
	startRotate := time.Now()
	bc.SetForwarder(c2)
	duration := time.Since(startRotate)

	// 验证切换是否快速 (不应阻塞等待旧连接关闭)
	if duration > 100*time.Millisecond {
		t.Errorf("SetForwarder took too long: %v, expected instant return", duration)
	}

	// --- 阶段 3: 验证 C2 接管 ---
	// 写入 B，应该到达 S2
	bc.B.Write([]byte("msg2"))

	s2.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, _, err := s2.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("C2 communication failed (Read S2): %v", err)
	}
	if string(buf[:n]) != "msg2" {
		t.Errorf("S2 got wrong data: %s", buf[:n])
	}

	// 回复 B，应该通过 C2 回来
	s2.WriteToUDP([]byte("reply2"), c2.LocalAddr().(*net.UDPAddr))
	bc.B.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err = bc.B.Read(buf)
	if err != nil {
		t.Fatalf("C2 communication failed (Read B): %v", err)
	}
	if string(buf[:n]) != "reply2" {
		t.Errorf("B got wrong reply: %s", buf[:n])
	}

	// --- 阶段 4: 验证 C1 被清理/隔离 ---
	// 稍等片刻让 goroutine 退出
	time.Sleep(100 * time.Millisecond)

	// 验证 C1 无法再发送数据 (虽然 UDP 是无连接的，但 Bridge 应该不再向 C1 写入)
	// 验证 Bridge B 不再接收 S1 的数据
	s1.WriteToUDP([]byte("zombie msg"), c1.LocalAddr().(*net.UDPAddr))

	// 尝试从 B 读，应该读不到 "zombie msg"，或者读超时 (因为我们期待的是 C2 的数据)
	// 注意：这里可能有残留数据风险，但在本测试逻辑中，C2 没有发数据，所以 B 应该读超时
	bc.B.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	n, err = bc.B.Read(buf)
	if err == nil {
		t.Errorf("B unexpectedly received data from dead C1: %s", buf[:n])
	} else if !strings.Contains(err.Error(), "timeout") {
		// 如果不是超时错误，可能是其他异常
		t.Logf("Got expected error reading B (timeout expected): %v", err)
	}

	// 验证 C1 本身已被 Close
	// 尝试向 C1 写入，如果是已关闭的连接，Go 的 netFD 通常会报错 "use of closed network connection"
	_, err = c1.Write([]byte("test"))
	if err == nil {
		t.Errorf("Old connection C1 should be closed, but Write succeeded")
	} else {
		t.Logf("Verified C1 is closed: %v", err)
	}
}

// 关闭测试: 验证 Close 清理所有资源
func TestBridgeConn_Close(t *testing.T) {
	bc, err := NewBridge()
	if err != nil {
		t.Fatal(err)
	}
	s, c := createUDPComponent(t)
	defer s.Close()

	bc.SetForwarder(c)

	// 确保运行起来
	bc.B.Write([]byte("ping"))
	time.Sleep(50 * time.Millisecond)

	// 关闭 Bridge
	t.Log("Closing Bridge")
	bc.Close()

	// 验证 1: 内部连接 B 应该关闭
	_, err = bc.B.Write([]byte("pong"))
	if err == nil {
		t.Error("Write to B should fail after Close")
	}

	// 验证 2: 外部连接 C 应该被关闭
	time.Sleep(50 * time.Millisecond) // 等待异步清理
	_, err = c.Write([]byte("test"))
	if err == nil {
		t.Error("External connection C should be closed after Bridge Close")
	} else {
		t.Logf("External C closed as expected: %v", err)
	}
}

// 压力/并发测试 (可选): 快速连续切换
func TestBridgeConn_RapidRotation(t *testing.T) {
	bc, err := NewBridge()
	if err != nil {
		t.Fatal(err)
	}
	defer bc.Close()

	// 连续切换 10 次
	for i := 0; i < 10; i++ {
		s, c := createUDPComponent(t)
		// 这里的 s 不 Close 也没关系，作为测试垃圾丢弃，或者用切片收集起来最后 Close
		defer s.Close()

		bc.SetForwarder(c)

		// 每次切换写一点数据，确保没 Panic
		msg := fmt.Sprintf("data-%d", i)
		bc.B.Write([]byte(msg))

		// 稍微间隔一点点，模拟极高频切换
		time.Sleep(10 * time.Millisecond)
	}

	t.Log("Rapid rotation finished without panic")
}
