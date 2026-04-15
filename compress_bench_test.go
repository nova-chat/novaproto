package novaproto_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/nova-chat/novaproto/compress"
	"github.com/nova-chat/novaproto/serializer"
)

// A realistic chat-history payload: users, messages with text, reactions
// and small attachments. Text is drawn from a fixed phrase pool so the
// data has real-world redundancy (compressible) while UUIDs and
// timestamps stay high-entropy (not compressible).
type benchUser struct {
	ID       uuid.UUID
	Name     string
	Nickname string
	Avatar   [32]byte
	JoinedAt int64
}

type benchMessage struct {
	ID          uuid.UUID
	AuthorID    uuid.UUID
	ChannelID   uuid.UUID
	Timestamp   int64
	Seq         uint64
	Text        string
	Reactions   []string
	Attachments [][]byte
}

type benchHistory struct {
	Channel  string
	Users    []benchUser
	Messages []benchMessage
}

func makeBenchHistory() benchHistory {
	phrases := []string{
		"Привет, как дела?",
		"Отлично, а у тебя?",
		"Нормально, работаю над проектом novaproto",
		"Какие планы на выходные?",
		"Думаю поехать за город с друзьями",
		"Звучит классно, можно я с тобой?",
		"Конечно, встретимся в 10 утра у метро",
		"Договорились, до встречи завтра!",
		"Как прошла встреча сегодня с командой?",
		"Продуктивно, обсудили архитектуру и компрессию",
	}
	reactions := []string{"👍", "❤️", "😂", "🔥", "👏"}

	mkUUID := func(seed uint64) uuid.UUID {
		var id uuid.UUID
		binary.BigEndian.PutUint64(id[0:8], seed)
		binary.BigEndian.PutUint64(id[8:16], seed*2654435761)
		return id
	}

	users := make([]benchUser, 5)
	for i := range users {
		u := &users[i]
		u.ID = mkUUID(uint64(100 + i))
		u.Name = fmt.Sprintf("Пользователь %d", i)
		u.Nickname = fmt.Sprintf("@user%d", i)
		u.JoinedAt = 1_700_000_000 + int64(i)*86400
		for j := range u.Avatar {
			u.Avatar[j] = byte(i*31 + j)
		}
	}

	messages := make([]benchMessage, 50)
	for i := range messages {
		m := &messages[i]
		m.ID = mkUUID(uint64(1000 + i))
		m.AuthorID = users[i%len(users)].ID
		m.ChannelID = mkUUID(1)
		m.Timestamp = 1_700_000_000_000_000_000 + int64(i)*60_000_000_000
		m.Seq = uint64(i)
		m.Text = phrases[i%len(phrases)]
		if i%3 == 0 {
			m.Reactions = []string{reactions[i%len(reactions)]}
		}
		if i%10 == 0 {
			att := make([]byte, 256)
			for j := range att {
				att[j] = byte((i + j) % 256)
			}
			m.Attachments = [][]byte{att}
		}
	}

	return benchHistory{
		Channel:  "#general",
		Users:    users,
		Messages: messages,
	}
}

// TestCompressionStatistics prints a human-readable summary of what
// serializer.Marshal + compress.Compress produce on a realistic chat
// history payload, and verifies the full roundtrip.
//
// Run with: go test -v -run TestCompressionStatistics ./novaproto/
func TestCompressionStatistics(t *testing.T) {
	data := makeBenchHistory()

	raw, err := serializer.Marshal(data)
	if err != nil {
		t.Fatalf("serializer.Marshal: %v", err)
	}

	compressed, algo := compress.Compress(raw, 0)

	ratio := float64(len(compressed)) / float64(len(raw)) * 100
	savings := 100 - ratio

	t.Logf("serializer raw:        %6d bytes", len(raw))
	t.Logf("compress.Compress:     %6d bytes  (algo=%d)", len(compressed), algo)
	t.Logf("ratio compressed/raw:  %5.1f%%", ratio)
	t.Logf("bytes saved:           %5.1f%%", savings)

	// Roundtrip: Decompress → Unmarshal must yield the original struct.
	decompressed, err := compress.Decompress(compressed, algo)
	if err != nil {
		t.Fatalf("compress.Decompress: %v", err)
	}
	if !bytes.Equal(decompressed, raw) {
		t.Fatalf("decompressed bytes differ from serialized form")
	}
	var back benchHistory
	if err := serializer.Unmarshal(decompressed, &back); err != nil {
		t.Fatalf("serializer.Unmarshal: %v", err)
	}
	if back.Channel != data.Channel ||
		len(back.Users) != len(data.Users) ||
		len(back.Messages) != len(data.Messages) {
		t.Errorf("structural mismatch after roundtrip")
	}
}

// BenchmarkSerializeOnly is the baseline — serialize without compressing.
func BenchmarkSerializeOnly(b *testing.B) {
	data := makeBenchHistory()
	raw, _ := serializer.Marshal(data)
	b.ReportMetric(float64(len(raw)), "bytes/op")
	b.SetBytes(int64(len(raw)))
	for b.Loop() {
		_, _ = serializer.Marshal(data)
	}
}

// BenchmarkCompressOnly measures compress.Compress on pre-serialized bytes,
// isolating compression cost from serialization cost.
func BenchmarkCompressOnly(b *testing.B) {
	data := makeBenchHistory()
	raw, _ := serializer.Marshal(data)
	compressed, _ := compress.Compress(raw, 0)
	b.ReportMetric(float64(len(raw)), "raw_bytes")
	b.ReportMetric(float64(len(compressed)), "comp_bytes")
	b.ReportMetric(float64(len(compressed))/float64(len(raw))*100, "ratio_%")
	b.SetBytes(int64(len(raw)))
	for b.Loop() {
		_, _ = compress.Compress(raw, 0)
	}
}

// BenchmarkDecompressOnly measures compress.Decompress on a pre-compressed
// frame — the receive hot path after the transport layer has handed off
// the payload bytes.
func BenchmarkDecompressOnly(b *testing.B) {
	data := makeBenchHistory()
	raw, _ := serializer.Marshal(data)
	compressed, algo := compress.Compress(raw, 0)
	b.SetBytes(int64(len(raw)))
	for b.Loop() {
		_, _ = compress.Decompress(compressed, algo)
	}
}

// BenchmarkSendPipeline measures the full sender path:
// serializer.Marshal → compress.Compress.
func BenchmarkSendPipeline(b *testing.B) {
	data := makeBenchHistory()
	raw, _ := serializer.Marshal(data)
	compressed, _ := compress.Compress(raw, 0)
	b.ReportMetric(float64(len(raw)), "raw_bytes")
	b.ReportMetric(float64(len(compressed)), "comp_bytes")
	b.ReportMetric(float64(len(compressed))/float64(len(raw))*100, "ratio_%")
	b.SetBytes(int64(len(raw)))
	for b.Loop() {
		buf, _ := serializer.Marshal(data)
		_, _ = compress.Compress(buf, 0)
	}
}

// BenchmarkReceivePipeline measures the full receiver path:
// compress.Decompress → serializer.Unmarshal.
func BenchmarkReceivePipeline(b *testing.B) {
	data := makeBenchHistory()
	raw, _ := serializer.Marshal(data)
	compressed, algo := compress.Compress(raw, 0)
	b.SetBytes(int64(len(raw)))
	for b.Loop() {
		decoded, _ := compress.Decompress(compressed, algo)
		var back benchHistory
		_ = serializer.Unmarshal(decoded, &back)
	}
}
