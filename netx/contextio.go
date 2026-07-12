package netx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// WaitContext waits for delay or returns early when ctx is done.
func WaitContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// ReadFullWithContext reads exactly len(buf) bytes while polling ctx through
// temporary read deadlines. Cancellation latency is bounded by pollInterval
// when conn honors deadlines. The read deadline is cleared before returning;
// any deadline configured by the caller before this call is not preserved.
func ReadFullWithContext(ctx context.Context, conn net.Conn, buf []byte, timeout, pollInterval time.Duration) (int, error) {
	return transferFullWithContext(ctx, buf, timeout, pollInterval, conn.SetReadDeadline, conn.Read)
}

// WriteFullWithContext writes exactly len(buf) bytes while polling ctx through
// temporary write deadlines. Cancellation latency is bounded by pollInterval
// when conn honors deadlines. The write deadline is cleared before returning;
// any deadline configured by the caller before this call is not preserved.
func WriteFullWithContext(ctx context.Context, conn net.Conn, buf []byte, timeout, pollInterval time.Duration) (int, error) {
	return transferFullWithContext(ctx, buf, timeout, pollInterval, conn.SetWriteDeadline, conn.Write)
}

func transferFullWithContext(
	ctx context.Context,
	buf []byte,
	timeout time.Duration,
	pollInterval time.Duration,
	setDeadline func(time.Time) error,
	transfer func([]byte) (int, error),
) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if pollInterval <= 0 {
		return 0, fmt.Errorf("invalid I/O poll interval: %s", pollInterval)
	}

	deadline := time.Now().Add(timeout)
	total := 0
	defer setDeadline(time.Time{})

	for total < len(buf) {
		if err := ctx.Err(); err != nil {
			return total, err
		}

		now := time.Now()
		if !now.Before(deadline) {
			return total, context.DeadlineExceeded
		}

		operationDeadline := now.Add(pollInterval)
		if operationDeadline.After(deadline) {
			operationDeadline = deadline
		}
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(operationDeadline) {
			operationDeadline = ctxDeadline
		}
		if err := setDeadline(operationDeadline); err != nil {
			return total, err
		}

		n, err := transfer(buf[total:])
		total += n
		if err == nil {
			if n == 0 {
				return total, io.ErrNoProgress
			}
			continue
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return total, ctxErr
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			continue
		}
		return total, err
	}

	return total, nil
}
