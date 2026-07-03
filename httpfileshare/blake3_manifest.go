package httpfileshare

import (
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"runtime"
	"sync"

	"github.com/zeebo/blake3"
)

const (
	blake3ManifestAlgo       = "blake3"
	defaultManifestBlockSize = int64(8 * 1024 * 1024)
	minManifestBlockSize     = int64(64 * 1024)
	maxManifestBlockSize     = int64(64 * 1024 * 1024)
	maxManifestHashWorkers   = 8
)

type blake3ManifestFileRecord struct {
	Type      string `json:"type"`
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	ModTime   string `json:"mod_time"`
	Algo      string `json:"algo"`
	BlockSize int64  `json:"block_size"`
}

type blake3ManifestBlockRecord struct {
	Type   string `json:"type"`
	Index  int    `json:"index"`
	Offset int64  `json:"offset"`
	Size   int64  `json:"size"`
	Hash   string `json:"hash"`
}

func normalizeManifestBlockSize(blockSize int64) int64 {
	if blockSize <= 0 {
		return defaultManifestBlockSize
	}
	if blockSize < minManifestBlockSize {
		return minManifestBlockSize
	}
	if blockSize > maxManifestBlockSize {
		return maxManifestBlockSize
	}
	return blockSize
}

func blake3BlockHashes(file fs.File, fileSize, blockSize int64) ([]blake3ManifestBlockRecord, error) {
	if fileSize < 0 {
		return nil, fmt.Errorf("negative file size")
	}
	blockSize = normalizeManifestBlockSize(blockSize)
	blockCount := int((fileSize + blockSize - 1) / blockSize)
	blocks := make([]blake3ManifestBlockRecord, blockCount)
	if blockCount == 0 {
		return blocks, nil
	}

	if readerAt, ok := file.(io.ReaderAt); ok {
		return blake3BlockHashesParallel(readerAt, fileSize, blockSize, blocks)
	}
	return blake3BlockHashesSerial(file, fileSize, blockSize, blocks)
}

func blake3BlockHashesParallel(readerAt io.ReaderAt, fileSize, blockSize int64, blocks []blake3ManifestBlockRecord) ([]blake3ManifestBlockRecord, error) {
	workerCount := runtime.GOMAXPROCS(0)
	if workerCount > maxManifestHashWorkers {
		workerCount = maxManifestHashWorkers
	}
	if workerCount > len(blocks) {
		workerCount = len(blocks)
	}
	if workerCount < 1 {
		workerCount = 1
	}

	jobs := make(chan int)
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex

	setErr := func(err error) {
		errMu.Lock()
		defer errMu.Unlock()
		if firstErr == nil {
			firstErr = err
		}
	}

	for range workerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				offset, size := manifestBlockBounds(index, fileSize, blockSize)
				sum, err := blake3HashReader(io.NewSectionReader(readerAt, offset, size), size)
				if err != nil {
					setErr(err)
					continue
				}
				blocks[index] = blake3ManifestBlockRecord{
					Type:   "block",
					Index:  index,
					Offset: offset,
					Size:   size,
					Hash:   hex.EncodeToString(sum[:]),
				}
			}
		}()
	}

	for index := range blocks {
		errMu.Lock()
		hasErr := firstErr != nil
		errMu.Unlock()
		if hasErr {
			break
		}
		jobs <- index
	}
	close(jobs)
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}
	return blocks, nil
}

func blake3BlockHashesSerial(reader io.Reader, fileSize, blockSize int64, blocks []blake3ManifestBlockRecord) ([]blake3ManifestBlockRecord, error) {
	for index := range blocks {
		offset, size := manifestBlockBounds(index, fileSize, blockSize)
		sum, err := blake3HashReader(reader, size)
		if err != nil {
			return nil, err
		}
		blocks[index] = blake3ManifestBlockRecord{
			Type:   "block",
			Index:  index,
			Offset: offset,
			Size:   size,
			Hash:   hex.EncodeToString(sum[:]),
		}
	}
	return blocks, nil
}

func manifestBlockBounds(index int, fileSize, blockSize int64) (offset, size int64) {
	offset = int64(index) * blockSize
	size = blockSize
	if remaining := fileSize - offset; remaining < size {
		size = remaining
	}
	return offset, size
}

func blake3HashReader(reader io.Reader, size int64) ([32]byte, error) {
	hasher := blake3.New()
	if _, err := io.CopyN(hasher, reader, size); err != nil {
		return [32]byte{}, err
	}
	var sum [32]byte
	copy(sum[:], hasher.Sum(nil))
	return sum, nil
}
