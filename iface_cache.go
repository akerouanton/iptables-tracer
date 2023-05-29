package main

import (
	"context"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type IfaceCache struct {
	mu     sync.RWMutex
	ifaces map[int]netlink.Link
}

func (cache *IfaceCache) Watch(ctx context.Context) error {
	ch := make(chan netlink.LinkUpdate)
	doneCh := make(chan struct{})

	if err := netlink.LinkSubscribeWithOptions(ch, doneCh, netlink.LinkSubscribeOptions{
		ListExisting: true,
	}); err != nil {
		return err
	}

	cache.ifaces = map[int]netlink.Link{}

	for {
		select {
		case evt := <-ch:
			cache.mu.Lock()
			if evt.Header.Type == unix.RTM_NEWLINK {
				cache.ifaces[int(evt.Index)] = evt.Link
			} else if evt.Header.Type == unix.RTM_DELLINK {
				delete(cache.ifaces, int(evt.Index))
			}
			cache.mu.Unlock()
		case <-ctx.Done():
			close(doneCh)
			return nil
		}
	}
}

// IndexToName is the equivalent of nlif_index2name from libnfnetlink
func (cache *IfaceCache) IndexToName(id *uint32) (string, bool) {
	if id == nil {
		return "", true
	}

	cache.mu.RLock()
	defer cache.mu.RUnlock()

	link, ok := cache.ifaces[int(*id)]
	if !ok {
		return "", false
	}

	return link.Attrs().Name, true
}
