package oauth

import (
	"sort"
	"sync"
	"time"
)

type (
	MemCache struct {
		Maximum int
		mu      sync.RWMutex
		values  map[string]*cacheValue
		keys    []*cacheValue
	}

	cacheValue struct {
		key   string
		value string
		time  time.Time
	}

	Cache interface {
		Get(key string) (value string, err error)
		Set(key string, value string) (err error)
	}
)

func (c *MemCache) Get(key string) (value string, err error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.values == nil {
		return
	}
	if v, ok := c.values[key]; ok {
		value = v.value
	}
	return
}

func (c *MemCache) Set(key string, value string) (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.values == nil {
		c.values = make(map[string]*cacheValue, 0)
		c.keys = make([]*cacheValue, 0)
	}

	// 增加
	cacheValue := &cacheValue{
		key:   key,
		value: value,
		time:  time.Now(),
	}
	if _, ok := c.values[key]; !ok {
		c.keys = append(c.keys, cacheValue)
	}
	c.values[key] = cacheValue

	// 减少
	if len(c.keys) > c.Maximum {
		sort.Sort(c)
		n := (c.Maximum / 2)
		for i := 0; i < n; i++ {
			key := c.keys[i].key
			delete(c.values, key)
		}
		c.keys = c.keys[n:]
	}
	return
}

func (c *MemCache) Len() int {
	return len(c.keys)
}
func (c *MemCache) Less(i, j int) bool {
	return c.keys[i].time.Unix() < c.keys[i].time.Unix()
}
func (c *MemCache) Swap(i, j int) {
	c.keys[i], c.keys[j] = c.keys[j], c.keys[i]
}
