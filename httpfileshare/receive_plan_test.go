package httpfileshare

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestDirectoryOrderingLeavesFilesAndLinksInListingOrder(t *testing.T) {
	files := []FileInfo{
		{Path: "/a/b/c", IsDir: true},
		{Path: "/z/file"},
		{Path: "/z", IsDir: true},
		{Path: "/a/b", IsDir: true},
		{Path: "/a", IsDir: true},
		{Path: "/alias", IsDir: true, LinkTarget: "a"},
		{Path: "/a/first"},
	}
	actions := map[string]ReceiveAction{
		"/a/b/c": ReceiveDirectory, "/z/file": ReceiveContent, "/z": ReceiveDirectory,
		"/a/b": ReceiveDirectory, "/a": ReceiveDirectory, "/alias": ReceiveLink, "/a/first": ReceiveContent,
	}
	original := append([]FileInfo(nil), files...)
	var ordered []string
	for _, dir := range orderedReceiveDirectories(files, actions) {
		ordered = append(ordered, files[dir.index].Path)
	}
	if !reflect.DeepEqual(ordered, []string{"/z", "/a", "/a/b", "/a/b/c"}) {
		t.Fatalf("directories=%v", ordered)
	}
	if !reflect.DeepEqual(files, original) {
		t.Fatal("reordered the source listing")
	}
}

func TestIncrementalPlannerKeepsOldDecisionsAndResolvesNewTargets(t *testing.T) {
	p, err := newReceivePlanner([]FileInfo{
		{Path: "/pending", LinkTarget: "later"},
		{Path: "/dir/child"}, // inferred parent must remain a directory
	})
	if err != nil {
		t.Fatal(err)
	}
	actions := make(map[string]ReceiveAction)
	visit := func(file FileInfo, action ReceiveAction) { actions[file.Path] = action }
	p.visitFrom(0, visit)
	first := len(p.files)
	if err := p.add([]FileInfo{{Path: "/later"}, {Path: "/new", LinkTarget: "pending"}, {Path: "/dir", IsDir: true}}); err != nil {
		t.Fatal(err)
	}
	p.visitFrom(first, visit)
	if actions["/pending"] != ReceiveContent || actions["/new"] != ReceiveLink {
		t.Fatalf("actions=%v", actions)
	}
	if len(actions) != 5 {
		t.Fatalf("actions=%v", actions)
	}
	bad, err := newReceivePlanner([]FileInfo{{Path: "/missing/child"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := bad.add([]FileInfo{{Path: "/missing"}}); err == nil {
		t.Fatal("accepted a non-directory at an inferred parent")
	}
}

func TestMemoizedLinkChainsKeepCycleAndDepthLimits(t *testing.T) {
	files := []FileInfo{{Path: "/file"}}
	for i := 0; i < 64; i++ {
		target := "file"
		if i < 63 {
			target = fmt.Sprintf("link%d", i+1)
		}
		files = append(files, FileInfo{Path: fmt.Sprintf("/link%d", i), LinkTarget: target})
	}
	files = append(files, FileInfo{Path: "/cycleA", LinkTarget: "cycleB"}, FileInfo{Path: "/cycleB", LinkTarget: "cycleA"})
	for _, reverse := range []bool{false, true} {
		if reverse {
			for i, j := 0, len(files)-1; i < j; i, j = i+1, j-1 {
				files[i], files[j] = files[j], files[i]
			}
		}
		plan, err := PlanReceive(files)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range plan {
			want := ReceiveLink
			if entry.File.Path == "/file" || entry.File.Path == "/link0" || strings.HasPrefix(entry.File.Path, "/cycle") {
				want = ReceiveContent
			}
			if entry.Action != want {
				t.Fatalf("reverse=%v %s: %s want %s", reverse, entry.File.Path, entry.Action, want)
			}
		}
	}
}

func performanceListing(fileCount, dirCount int) ([]FileInfo, map[string]ReceiveAction) {
	files := make([]FileInfo, 0, fileCount+dirCount)
	actions := make(map[string]ReceiveAction, fileCount+dirCount)
	dirs := make([]string, dirCount)
	for i := range dirs {
		dirs[i] = "/root/" + strings.Repeat("level/", i%12) + fmt.Sprintf("dir%04d", i)
		files = append(files, FileInfo{Path: dirs[i], IsDir: true})
		actions[dirs[i]] = ReceiveDirectory
	}
	for i := 0; i < fileCount; i++ {
		name := dirs[i%dirCount] + fmt.Sprintf("/file%06d", i)
		files = append(files, FileInfo{Path: name, Size: 1024})
		actions[name] = ReceiveContent
	}
	return files, actions
}

// Both variants pay the same buffer-reset cost. The old variant is retained
// only as a benchmark baseline for the full-list sort being removed.
func BenchmarkReceiveOrdering(b *testing.B) {
	files, actions := performanceListing(100000, 1000)
	for _, name := range []string{"FullList", "DirectoriesOnly"} {
		b.Run(name, func(b *testing.B) {
			work := make([]FileInfo, len(files))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				copy(work, files)
				if name == "FullList" {
					sort.SliceStable(work, func(i, j int) bool { return strings.Count(work[i].Path, "/") < strings.Count(work[j].Path, "/") })
				} else {
					orderedReceiveDirectories(work, actions)
				}
			}
		})
	}
}

func BenchmarkReceivePlanningBatches(b *testing.B) {
	initial, _ := performanceListing(50000, 500)
	var batches [][]FileInfo
	for batch := 0; batch < 12; batch++ {
		var files []FileInfo
		for i := 0; i < 100; i++ {
			files = append(files, FileInfo{Path: fmt.Sprintf("/expanded%d/file%d", batch, i)})
		}
		batches = append(batches, files)
	}
	for _, name := range []string{"FullReplan", "Incremental"} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if name == "FullReplan" {
					files := append([]FileInfo(nil), initial...)
					if _, err := PlanReceive(files); err != nil {
						b.Fatal(err)
					}
					for _, batch := range batches {
						files = append(files, batch...)
						if _, err := PlanReceive(files); err != nil {
							b.Fatal(err)
						}
					}
				} else {
					p, err := newReceivePlanner(append([]FileInfo(nil), initial...))
					if err != nil {
						b.Fatal(err)
					}
					visit := func(FileInfo, ReceiveAction) {}
					p.visitFrom(0, visit)
					for _, batch := range batches {
						first := len(p.files)
						if err := p.add(batch); err != nil {
							b.Fatal(err)
						}
						p.visitFrom(first, visit)
					}
				}
			}
		})
	}
}
