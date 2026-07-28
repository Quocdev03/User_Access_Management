package blob

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalStorePutURLAndDelete(t *testing.T) {
	root := t.TempDir()
	store, err := NewLocalStore(root)
	if err != nil {
		t.Fatalf("NewLocalStore(): %v", err)
	}
	key := "avatars/avatar-id.png"
	if err := store.Put(
		context.Background(),
		key,
		bytes.NewBufferString("image-bytes"),
	); err != nil {
		t.Fatalf("Put(): %v", err)
	}
	stored, err := os.ReadFile(filepath.Join(root, "avatars", "avatar-id.png"))
	if err != nil {
		t.Fatalf("ReadFile(): %v", err)
	}
	if string(stored) != "image-bytes" {
		t.Fatalf("stored content = %q", stored)
	}
	if got := store.URL(key); got != "/uploads/avatars/avatar-id.png" {
		t.Fatalf("URL() = %q", got)
	}
	if err := store.Delete(context.Background(), key); err != nil {
		t.Fatalf("Delete(): %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "avatars", "avatar-id.png")); !os.IsNotExist(err) {
		t.Fatalf("deleted blob stat error = %v", err)
	}
}

func TestLocalStoreRejectsTraversalAndPreservesExternalReferences(t *testing.T) {
	store, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore(): %v", err)
	}
	for _, key := range []string{
		"../escape.png",
		"avatars/../escape.png",
		"avatars/../../escape.png",
		"/outside/escape.png",
	} {
		if err := store.Put(
			context.Background(),
			key,
			bytes.NewBufferString("x"),
		); err == nil {
			t.Fatalf("Put(%q) accepted unsafe key", key)
		}
	}
	if err := store.Delete(
		context.Background(),
		"https://cdn.example.test/avatar.png",
	); err != nil {
		t.Fatalf("Delete(external URL): %v", err)
	}
	if got := store.URL("/uploads/avatars/legacy.png"); got != "/uploads/avatars/legacy.png" {
		t.Fatalf("legacy URL = %q", got)
	}
	if got := store.URL("avatars/../escape.png"); got != "" {
		t.Fatalf("unsafe URL = %q", got)
	}
	if err := store.Delete(
		context.Background(),
		"avatars/../escape.png",
	); err == nil {
		t.Fatal("Delete() accepted normalized key outside avatars")
	}
}
