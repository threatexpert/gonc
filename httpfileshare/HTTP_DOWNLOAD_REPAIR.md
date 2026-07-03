# HTTP Download Repair Protocol

This document describes the enhanced HTTP download resume/repair behavior.
It is intended for GUI clients or other clients that call the `httpfileshare`
HTTP server and implement their own downloader.

## Goal

The client should not resume downloads by file size alone. A local file may have
the same prefix size as the remote file but contain stale or modified data.

The enhanced flow uses a BLAKE3 block manifest from the server to decide:

- which local blocks can be kept;
- which blocks must be downloaded again;
- whether the local file should be truncated;
- whether repair is too expensive and a full re-download is better.

## Server Manifest API

For a remote file, request a BLAKE3 block manifest:

```http
GET /path/to/file.bin?manifest=blake3&block_size=8388608
Accept: application/json
Accept-Encoding: zstd, gzip
```

The response is NDJSON:

```http
Content-Type: application/x-ndjson
```

The first line is the file record:

```json
{"type":"file","path":"/path/to/file.bin","size":123456789,"mod_time":"2026-07-03T12:00:00Z","algo":"blake3","block_size":8388608}
```

Each following line is one block record:

```json
{"type":"block","index":0,"offset":0,"size":8388608,"hash":"..."}
{"type":"block","index":1,"offset":8388608,"size":8388608,"hash":"..."}
```

The default block size is `8MB`. The server clamps requested block sizes to the
range `64KB` through `64MB`.

The manifest response may be compressed. The client should decode it according
to `Content-Encoding`.

Supported encodings:

- empty / `identity`
- `zstd`
- `gzip`

If the response uses an unknown encoding, treat the manifest as unavailable and
fall back to a full file download.

## Client Decision Tree

For each remote file:

```text
1. Local file does not exist
   => Full download.

2. Local file exists, and localSize == remoteSize && localMtime == remoteModTime
   => Treat as complete and skip.

3. Local file exists, but condition 2 is false
   => Enter BLAKE3 repair flow.
```

Do not blindly do this old behavior:

```text
localSize < remoteSize => Range: bytes=localSize-
```

Range download should happen only after block hashes confirm which local content
can be reused.

## Repair Flow

1. Request the remote BLAKE3 manifest.
2. Compute local BLAKE3 block hashes using the manifest `block_size`.
3. Compare local blocks against remote blocks by offset and size.

For each remote block:

```text
If offset + size > localSize:
  Mark as missing. It must be downloaded.

If localBlockHash != remoteBlockHash:
  Mark as dirty. It must be downloaded.

Otherwise:
  Keep the local block.
```

Merge adjacent dirty/missing blocks into larger ranges.

Example range request:

```http
GET /path/to/file.bin
Range: bytes=8388608-16777215
Accept-Encoding: zstd, gzip
```

The range response may also be compressed. The client must decode the body using
`Content-Encoding` before writing it to the local file.

Supported encodings:

- empty / `identity`
- `zstd`
- `gzip`

If a range response uses an unknown encoding, treat range repair as unsupported
and fall back to a full file download.

## Why Compressed Range Responses Are Valid Here

The current `httpfileshare` server applies compression after `http.ServeContent`
has selected the original file range.

The flow is:

```text
ServeContent reads original file bytes for the requested range.
The selected range bytes are written to the compression writer.
The compressed range body is sent to the client.
```

So the response body is the compressed form of the original range bytes, not a
slice of a whole-file compressed stream.

Therefore, a client can safely repair with compressed range responses if it:

1. decodes the response body according to `Content-Encoding`;
2. writes the decoded bytes to the local file at the requested range offset;
3. verifies that decoded byte count equals the expected range size.

## Applying Repair

For each merged range:

```text
1. Send a Range request.
2. Decode the response body using Content-Encoding.
3. Write decoded bytes to local file at the range offset.
4. Verify decoded bytes written == range size.
```

After all ranges complete:

```text
If localSize > remoteSize:
  Truncate local file to remoteSize.

Set local file mtime to remoteModTime.
```

## Full Re-download Thresholds

The CLI client currently uses these thresholds:

```text
dirty/missing range count > 128
  => Full re-download.

dirty/missing total bytes > 50% of remoteSize
  => Full re-download.
```

GUI clients may reuse these thresholds or expose them as advanced settings.

## Typical Behavior

Remote file only appended data:

```text
Existing local blocks match.
Tail blocks are missing.
=> Download only the missing tail.
```

Remote file became shorter:

```text
Remote-sized prefix matches.
=> Download nothing, truncate local file.
```

Small in-place modification:

```text
Only the affected block hash differs.
=> Download and overwrite that dirty block.
```

Middle insertion/deletion causing offset shift:

```text
Many following blocks differ.
=> Usually exceeds threshold and falls back to full re-download.
```

Old server does not support manifest:

```text
Manifest request returns non-200.
=> Do not blindly resume. Full re-download.
```

## Logging / GUI Display Suggestions

Do not show one log line for every normal first-time file download or every
complete skip. That gets noisy.

Show repair-related events:

- local size;
- remote size;
- bytes kept;
- bytes to download;
- range request count;
- truncate size;
- full re-download fallback reason.

Example:

```text
Repair plan: local=16MB remote=20MB, keep=16MB, download=4MB in 1 range, truncate=0
Repair completed: downloaded 4MB, final size 20MB
```

Fallback examples:

```text
Repair check unavailable: server does not provide BLAKE3 manifest; falling back to full download
BLAKE3 repair unavailable or inefficient; re-downloading full file
```

## Directory List Compatibility

Recursive directory file list:

```http
GET /dir/
Accept: application/json
```

Non-recursive directory file list:

```http
GET /dir/?recursive=0
Accept: application/json
```

Only requests with `Accept: application/json` return NDJSON. A normal browser
directory request still returns HTML.
