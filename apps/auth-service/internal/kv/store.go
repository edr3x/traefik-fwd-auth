package kv

import "sync"

type keyValueStore struct {
	mu    sync.Mutex
	store map[string]string
}

func NewKeyValueStore() *keyValueStore {
	return &keyValueStore{
		store: make(map[string]string),
	}
}

func (kvs *keyValueStore) Set(key, value string) {
	kvs.mu.Lock()
	defer kvs.mu.Unlock()
	kvs.store[key] = value
}

func (kvs *keyValueStore) Get(key string) (string, bool) {
	kvs.mu.Lock()
	defer kvs.mu.Unlock()
	value, ok := kvs.store[key]
	return value, ok
}

func (kvs *keyValueStore) Delete(key string) {
	kvs.mu.Lock()
	defer kvs.mu.Unlock()
	delete(kvs.store, key)
}
