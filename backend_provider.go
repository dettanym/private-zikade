package zikade

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/plprobelab/zikade/private_routing"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/benbjohnson/clock"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/ipfs/go-cid"
	ds "github.com/ipfs/go-datastore"
	dsq "github.com/ipfs/go-datastore/query"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/multiformats/go-base32"
	"github.com/plprobelab/zikade/pb"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/exp/slog"

	"github.com/plprobelab/zikade/tele"
)

// ProvidersBackend implements the [Backend] interface and handles provider
// record requests for the "/providers/" namespace.
type ProvidersBackend struct {
	// namespace holds the namespace string - usually
	// this is set to namespaceProviders ("providers")
	namespace string

	// cfg is set to DefaultProviderBackendConfig by default
	cfg *ProvidersBackendConfig

	// log is convenience accessor of cfg.Logger
	log *slog.Logger

	// cache is a LRU cache for frequently requested records. It is populated
	// when peers request a record and pruned during garbage collection.
	// TODO: is that really so effective? The cache size is quite low either.
	cache *lru.Cache[string, providerSet]

	// addrBook holds a reference to the peerstore's address book to store and
	// fetch peer multiaddresses from (we don't save them in the datastore).
	addrBook peerstore.AddrBook

	// datastore is where we save the peer IDs providing a certain multihash.
	// The datastore must be thread-safe.
	// Note: The datastore does not map key = CID to value = PeerID
	// It maps key = CID || PeerID to value = expiry time
	datastore ds.Datastore

	// gcSkip is a sync map that marks records as to-be-skipped by the garbage
	// collection process. TODO: this is a sub-optimal pattern.
	gcSkip sync.Map

	// gcActive indicates whether the garbage collection loop is running
	gcCancelMu sync.RWMutex
	gcCancel   context.CancelFunc
	gcDone     chan struct{}
}

var (
	_ Backend   = (*ProvidersBackend)(nil)
	_ io.Closer = (*ProvidersBackend)(nil)
)

// ProvidersBackendConfig is used to construct a [ProvidersBackend]. Use
// [DefaultProviderBackendConfig] to get a default configuration struct and then
// modify it to your liking.
type ProvidersBackendConfig struct {
	// clk is an unexported field that's used for testing time related methods
	clk clock.Clock

	// ProvideValidity specifies for how long provider records are valid
	ProvideValidity time.Duration

	// AddressTTL specifies for how long we will keep around provider multi
	// addresses in the peerstore's address book. If such multiaddresses are
	// present we send them alongside the peer ID to the requesting peer. This
	// prevents the necessity for a second look for the multiaddresses on the
	// requesting peers' side.
	AddressTTL time.Duration

	// CacheSize specifies the LRU cache size
	CacheSize int

	// GCInterval defines how frequently garbage collection should run
	GCInterval time.Duration

	// Logger is the logger to use
	Logger *slog.Logger

	// Tele holds a reference to the telemetry struct to capture metrics and
	// traces.
	Tele *Telemetry

	// AddressFilter is a filter function that any addresses that we attempt to
	// store or fetch from the peerstore's address book need to pass through.
	// If you're manually configuring this backend, make sure to align the
	// filter with the one configured in [Config.AddressFilter].
	AddressFilter AddressFilter
}

// DefaultProviderBackendConfig returns a default [ProvidersBackend]
// configuration. Use this as a starting point and modify it. If a nil
// configuration is passed to [NewBackendProvider], this default configuration
// here is used.
func DefaultProviderBackendConfig() (*ProvidersBackendConfig, error) {
	telemetry, err := NewWithGlobalProviders()
	if err != nil {
		return nil, fmt.Errorf("new telemetry: %w", err)
	}

	return &ProvidersBackendConfig{
		clk:             clock.New(),
		ProvideValidity: 48 * time.Hour, // empirically measured in: https://github.com/plprobelab/network-measurements/blob/master/results/rfm17-provider-record-liveness.md
		AddressTTL:      24 * time.Hour, // MAGIC
		CacheSize:       256,            // MAGIC
		GCInterval:      time.Hour,      // MAGIC
		Logger:          slog.Default(),
		Tele:            telemetry,
		AddressFilter:   AddrFilterIdentity, // verify alignment with [Config.AddressFilter]
	}, nil
}

// Store implements the [Backend] interface. In the case of a [ProvidersBackend]
// this method accepts a [peer.AddrInfo] as a value and stores it in the
// configured datastore.
func (p *ProvidersBackend) Store(ctx context.Context, key string, value any) (any, error) {
	addrInfo, ok := value.(peer.AddrInfo)
	if !ok {
		return nil, fmt.Errorf("expected peer.AddrInfo value type, got: %T", value)
	}

	rec := expiryRecord{
		expiry: p.cfg.clk.Now(),
	}

	cacheKey := newDatastoreKey(p.namespace, key).String()
	dsKey := newDatastoreKey(p.namespace, key, string(addrInfo.ID))
	if provs, ok := p.cache.Get(cacheKey); ok {
		provs.addProvider(addrInfo, rec.expiry)
	}

	filtered := p.cfg.AddressFilter(addrInfo.Addrs)
	p.addrBook.AddAddrs(addrInfo.ID, filtered, p.cfg.AddressTTL)

	_, found := p.gcSkip.LoadOrStore(dsKey.String(), struct{}{})

	if err := p.datastore.Put(ctx, dsKey, rec.MarshalBinary()); err != nil {
		p.cache.Remove(cacheKey)

		// if we have just added the key to the collectGarbage skip list, delete it again
		// if we have added it in a previous Store invocation, keep it around
		if !found {
			p.gcSkip.Delete(dsKey.String())
		}

		return nil, fmt.Errorf("datastore put: %w", err)
	}

	return addrInfo, nil
}

// Fetch implements the [Backend] interface. In the case of a [ProvidersBackend]
// this method returns a [providerSet] (unexported) that contains all peer IDs
// and known multiaddresses for the given key. The key parameter should be of
// the form "/providers/$binary_multihash".
func (p *ProvidersBackend) Fetch(ctx context.Context, key string) (any, error) {
	qKey := newDatastoreKey(p.namespace, key)

	if cached, ok := p.cache.Get(qKey.String()); ok {
		p.trackCacheQuery(ctx, true)
		return cached, nil
	}
	p.trackCacheQuery(ctx, false)

	q, err := p.datastore.Query(ctx, dsq.Query{Prefix: qKey.String()})
	if err != nil {
		return nil, err
	}

	defer func() {
		if err = q.Close(); err != nil {
			p.log.LogAttrs(ctx, slog.LevelWarn, "failed closing fetch query", slog.String("err", err.Error()))
		}
	}()

	now := p.cfg.clk.Now()
	mapCIDtoProviderSet := make(map[string]*providerSet)

	for e := range q.Next() {
		p.fetchLoopForEachElement(ctx, e, now, mapCIDtoProviderSet)
	}

	// each element of the map is initialized only after at least one key is found
	if mapCIDtoProviderSet[key] != nil {
		out := mapCIDtoProviderSet[key]
		p.cache.Add(qKey.String(), *out)
		return out, nil
	} else {
		return nil, ds.ErrNotFound
	}
}

// Validate verifies that the given values are of type [peer.AddrInfo]. Then it
// decides based on the number of attached multi addresses which value is
// "better" than the other. If there is a tie, Validate will return the index
// of the earliest occurrence.
func (p *ProvidersBackend) Validate(ctx context.Context, key string, values ...any) (int, error) {
	// short circuit if it's just a single value
	if len(values) == 1 {
		_, ok := values[0].(peer.AddrInfo)
		if !ok {
			return -1, fmt.Errorf("invalid type %T", values[0])
		}
		return 0, nil
	}

	bestIdx := -1
	for i, value := range values {
		addrInfo, ok := value.(peer.AddrInfo)
		if !ok {
			continue
		}

		if bestIdx == -1 {
			bestIdx = i
		} else if len(values[bestIdx].(peer.AddrInfo).Addrs) < len(addrInfo.Addrs) {
			bestIdx = i
		}
	}

	if bestIdx == -1 {
		return -1, fmt.Errorf("no value of correct type")
	}

	return bestIdx, nil
}

// Returns a map of CIDs to a list of provider peers who advertise that CID.
// The output map is used to conduct PIR requests in RunPIRforProviderPeersRecords.
// So internally, this method joins the datastore with the addrBook.
// Rationale is below:
// the datastore stores provider advertisements <CIDs, Peer ID providing that CID> --> expiry time.
// the addrbook (address book) maps peer IDs to their multiaddresses
// In Fetch, we first lookup the datastore for the peerIDs advertising a given CID key and then
// we use the peerID as an index to lookup the address book for the multiaddresses.
// We could lookup the datastore via PIR,
// but then we cannot use that PIR output as an index to lookup the addressbook privately.
// So we need to flatten out or join the two data structures for PIR to work.
func (p *ProvidersBackend) MapCIDBucketsToProviderPeerBytesForPIR(ctx context.Context, bucketIndexLength int) ([][]byte, error) {
	// get all records from the datastore
	q, err := p.datastore.Query(ctx, dsq.Query{Prefix: "/"}) // also works with the empty string
	if err != nil {
		return nil, err
	}

	// close the fetch query upon ending the function
	defer func() {
		if err = q.Close(); err != nil {
			p.log.LogAttrs(ctx, slog.LevelWarn, "failed closing fetch query", slog.String("err", err.Error()))
		}
	}()

	now := p.cfg.clk.Now()
	mapCIDtoProviderSet := make(map[string]*providerSet)

	for e := range q.Next() {
		p.fetchLoopForEachElement(ctx, e, now, mapCIDtoProviderSet)
	}

	// mapCIDtoProviderPeers := make(map[string]*pb.Message_CIDToProviderMap, len(mapCIDtoProviderSet))

	// bucketing logic
	if bucketIndexLength < 8 {
		return nil, fmt.Errorf("bucketIndexLength represents the length of the bucket index, in *bits* --- it must be greater than 8")
	}
	if bucketIndexLength%8 != 0 {
		// TODO: We should get rid of this requirement
		return nil, fmt.Errorf("bucketIndexLength represents the length of the bucket index, in *bits* --- it must be a multiple of 8")
	}
	buckets := make([][]*pb.Message_CIDToProviderMap, 1<<bucketIndexLength)

	// Transforms the set of providers into a PB Message that can be marshalled into a byte array.
	// This is based on how handleGetProviders processes the output of Fetch
	// they don't care about the set field of the providerSet (which maps peer IDs to times),
	// as we've already checked for expired provider advertisements.
	// There can be multiple providers for a given CID, so we first get a providerSet above and then
	// transform it into a list of *pb.Message_Peer
	for givenCID, providerSetForCID := range mapCIDtoProviderSet {
		addrInfos := make([]*pb.Message_Peer, len(providerSetForCID.providers))
		for _, provider := range providerSetForCID.providers {
			messagePeer := pb.FromAddrInfo(provider)
			addrInfos = append(addrInfos, messagePeer)
		}
		mesg := &pb.Message_CIDToProviderMap{
			Cid:           []byte(givenCID),
			ProviderPeers: addrInfos,
		}
		// marshalledRoutingEntries, err := proto.Marshal(mesg)
		// if err != nil {
		// 	return nil, fmt.Errorf("could not marshal peers in RT. Err: %s ", err)
		// }
		// mapCIDtoProviderPeers[givenCID] = mesg

		// putting the item in a bucket
		_, cidObj, err := cid.CidFromBytes([]byte(givenCID))
		if err != nil {
			return nil, err
		}
		cidHashed := cidObj.Hash()
		bucketIndexStr := cidHashed[2 : (bucketIndexLength/8)+2].HexString() // skipping first two bytes for hash function code, length
		bucketIndex, err := strconv.ParseInt(bucketIndexStr, 16, 64)
		if err != nil {
			return nil, err
		}

		if buckets[bucketIndex] == nil {
			buckets[bucketIndex] = make([]*pb.Message_CIDToProviderMap, 0)
		}
		buckets[bucketIndex] = append(buckets[bucketIndex], mesg)
	}

	bucketsInBytes := make([][]byte, len(buckets))
	for i, bucket := range buckets {
		// marshal the bucket
		plaintext, err := private_routing.MarshallPBToPlaintext(&pb.Message{
			Buckets: bucket,
		})
		if err != nil {
			return nil, err
		}
		bucketsInBytes[i] = plaintext
	}
	return bucketsInBytes, err
}

// // This should be similar to the previous function, but instead of returning a map of CIDs to a list of provider peers,
// // it should return a list of CID buckets. Each CID bucket is many (cid, provider peer) pairs.
// // This is essentially the same as the previous function, but each row is marshalled to a byte array.
// func (p *ProvidersBackend) MapCIDBucketsToProviderPeerBytesForPIR(ctx context.Context, bucketIndexLength int) ([][]byte, error) {
// 	return nil, fmt.Errorf("not implemented")
// }

// Close is here to implement the [io.Closer] interface. This will get called
// when the [DHT] "shuts down"/closes.
func (p *ProvidersBackend) Close() error {
	p.StopGarbageCollection()
	return nil
}

// StartGarbageCollection starts the garbage collection loop. The garbage
// collection interval can be configured with [ProvidersBackendConfig.GCInterval].
// The garbage collection loop can only be started a single time. Use
// [StopGarbageCollection] to stop the garbage collection loop.
func (p *ProvidersBackend) StartGarbageCollection() {
	p.gcCancelMu.Lock()
	if p.gcCancel != nil {
		p.log.Info("Provider backend's garbage collection is already running")
		p.gcCancelMu.Unlock()
		return
	}
	defer p.gcCancelMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	p.gcCancel = cancel
	p.gcDone = make(chan struct{})

	// init ticker outside the goroutine to prevent race condition with
	// clock mock in garbage collection test.
	ticker := p.cfg.clk.Ticker(p.cfg.GCInterval)

	go func() {
		defer close(p.gcDone)
		defer ticker.Stop()

		p.log.Info("Provider backend started garbage collection schedule")
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.collectGarbage(ctx)
			}
		}
	}()
}

// StopGarbageCollection stops the garbage collection loop started with
// [StartGarbageCollection]. If garbage collection is not running, this method
// is a no-op.
func (p *ProvidersBackend) StopGarbageCollection() {
	p.gcCancelMu.Lock()
	if p.gcCancel == nil {
		p.log.Info("Provider backend's garbage collection isn't running")
		p.gcCancelMu.Unlock()
		return
	}
	defer p.gcCancelMu.Unlock()

	p.gcCancel()
	<-p.gcDone
	p.gcDone = nil
	p.gcCancel = nil
	p.log.Info("Provider backend's garbage collection stopped")
}

// collectGarbage sweeps through the datastore and deletes all provider records
// that have expired. A record is expired if the
// [ProvidersBackendConfig].ProvideValidity is exceeded.
func (p *ProvidersBackend) collectGarbage(ctx context.Context) {
	p.log.Info("Provider backend starting garbage collection...")
	defer p.log.Info("Provider backend finished garbage collection!")

	// Faster to purge than garbage collecting
	p.cache.Purge()

	// erase map
	p.gcSkip.Range(func(key interface{}, value interface{}) bool {
		p.gcSkip.Delete(key)
		return true
	})

	// Now, kick off a GC of the datastore.
	q, err := p.datastore.Query(ctx, dsq.Query{Prefix: p.namespace})
	if err != nil {
		p.log.LogAttrs(ctx, slog.LevelWarn, "provider record garbage collection query failed", slog.String("err", err.Error()))
		return
	}

	defer func() {
		if err = q.Close(); err != nil {
			p.log.LogAttrs(ctx, slog.LevelWarn, "failed closing garbage collection query", slog.String("err", err.Error()))
		}
	}()

	for e := range q.Next() {
		if e.Error != nil {
			p.log.LogAttrs(ctx, slog.LevelWarn, "Garbage collection datastore entry contains error", slog.String("key", e.Key), slog.String("err", e.Error.Error()))
			continue
		}

		if _, found := p.gcSkip.Load(e.Key); found {
			continue
		}

		rec := expiryRecord{}
		now := p.cfg.clk.Now()
		if err = rec.UnmarshalBinary(e.Value); err != nil {
			p.log.LogAttrs(ctx, slog.LevelWarn, "Garbage collection provider record unmarshalling failed", slog.String("key", e.Key), slog.String("err", err.Error()))
			p.delete(ctx, ds.RawKey(e.Key))
		} else if now.Sub(rec.expiry) <= p.cfg.ProvideValidity {
			continue
		}

		// record expired -> garbage collect
		p.delete(ctx, ds.RawKey(e.Key))
	}
}

// trackCacheQuery updates the prometheus metrics about cache hit/miss performance
func (p *ProvidersBackend) trackCacheQuery(ctx context.Context, hit bool) {
	set := tele.FromContext(ctx,
		tele.AttrCacheHit(hit),
		tele.AttrRecordType("provider"),
	)
	p.cfg.Tele.LRUCache.Add(ctx, 1, metric.WithAttributeSet(set))
}

// delete is a convenience method to delete the record at the given datastore
// key. It doesn't return any error but logs it instead as a warning.
func (p *ProvidersBackend) delete(ctx context.Context, dsKey ds.Key) {
	if err := p.datastore.Delete(ctx, dsKey); err != nil {
		p.log.LogAttrs(ctx, slog.LevelWarn, "failed to remove provider record from disk", slog.String("key", dsKey.String()), slog.String("err", err.Error()))
	}
}

// expiryRecord is captures the information that gets written to the datastore
// for any provider record. This record doesn't include any peer IDs or
// multiaddresses because peer IDs are part of the key that this record gets
// stored under and multiaddresses are stored in the addrBook. This record
// just tracks the expiry time of the record. It implements binary marshalling
// and unmarshalling methods for easy (de)serialization into the datastore.
type expiryRecord struct {
	expiry time.Time
}

// MarshalBinary returns the byte slice that should be stored in the datastore.
// This method doesn't comply to the [encoding.BinaryMarshaler] interface
// because it doesn't return an error. We don't need the conformance here
// though.
func (e *expiryRecord) MarshalBinary() (data []byte) {
	buf := make([]byte, 16)
	n := binary.PutVarint(buf, e.expiry.UnixNano())
	return buf[:n]
}

// UnmarshalBinary is the inverse operation to the above MarshalBinary and is
// used to deserialize any blob of bytes that was previously stored in the
// datastore.
func (e *expiryRecord) UnmarshalBinary(data []byte) error {
	nsec, n := binary.Varint(data)
	if n == 0 {
		return fmt.Errorf("failed to parse time")
	}

	e.expiry = time.Unix(0, nsec)

	return nil
}

func (p *ProvidersBackend) deleteExpiredRecords(ctx context.Context, now time.Time, eKey string, eValue []byte) (isRecordExpired bool, record expiryRecord) {
	isRecordExpired = false
	rec := expiryRecord{}
	if err := rec.UnmarshalBinary(eValue); err != nil {
		p.log.LogAttrs(ctx, slog.LevelWarn, "Fetch provider record unmarshalling failed", slog.String("key", eKey), slog.String("err", err.Error()))
		p.delete(ctx, ds.RawKey(eKey))
		isRecordExpired = true
	} else if now.Sub(rec.expiry) > p.cfg.ProvideValidity {
		// record is expired
		p.delete(ctx, ds.RawKey(eKey))
		isRecordExpired = true
	}
	return isRecordExpired, rec
}

// A providerSet is used to gather provider information in a single struct. It
// also makes sure that the user doesn't add any duplicate peers.
type providerSet struct {
	providers []peer.AddrInfo
	set       map[peer.ID]time.Time
}

// addProvider adds the given address information to the providerSet. If the
// provider already exists, only the time is updated.
func (ps *providerSet) addProvider(addrInfo peer.AddrInfo, t time.Time) {
	_, found := ps.set[addrInfo.ID]
	if !found {
		ps.providers = append(ps.providers, addrInfo)
	}

	ps.set[addrInfo.ID] = t
}

// newDatastoreKey assembles a datastore for the given namespace and set of
// binary strings. For example, the IPNS record keys have the format:
// "/ipns/$binary_id" (see [Routing Record]). To construct a datastore key this
// function base32-encodes the $binary_id (and any additional path components)
// and joins the parts together separated by forward slashes.
//
// [Routing Record]: https://specs.ipfs.tech/ipns/ipns-record/#routing-record
func newDatastoreKey(namespace string, binStrs ...string) ds.Key {
	elems := make([]string, len(binStrs)+1)
	elems[0] = namespace
	for i, bin := range binStrs {
		elems[i+1] = base32.RawStdEncoding.EncodeToString([]byte(bin))
	}

	return ds.NewKey("/" + strings.Join(elems, "/"))
}

// newRoutingKey uses the given namespace and binary string key and constructs
// a new string of the format: /$namespace/$binStr
func newRoutingKey(namespace string, binStr string) string {
	buf := make([]byte, 0, 2+len(namespace)+len(binStr))
	buffer := bytes.NewBuffer(buf)
	buffer.WriteString("/" + namespace + "/")
	buffer.Write([]byte(binStr))
	return buffer.String()
}

func (p *ProvidersBackend) decomposeDatastoreKey(ctx context.Context, key string) (cid string, binPeerID []byte, err error) {
	idxPeerID := strings.LastIndex(key, "/")
	binPeerID, err = base32.RawStdEncoding.DecodeString(key[idxPeerID+1:])
	if err != nil {
		p.log.LogAttrs(ctx, slog.LevelWarn, "base32 key decoding error", slog.String("key", key[idxPeerID+1:]), slog.String("err", err.Error()))
		p.delete(ctx, ds.RawKey(key))
		return "", nil, err
	}
	idxCID := strings.LastIndex(key[:idxPeerID], "/")
	binCID, err := base32.RawStdEncoding.DecodeString(key[idxCID+1 : idxPeerID])
	if err != nil {
		p.log.LogAttrs(ctx, slog.LevelWarn, "base32 key decoding error", slog.String("key", key[idxPeerID+1:]), slog.String("err", err.Error()))
		p.delete(ctx, ds.RawKey(key))
		return "", nil, err
	}
	return string(binCID), binPeerID, nil
}

func (p *ProvidersBackend) fetchLoopForEachElement(ctx context.Context, e dsq.Result, now time.Time, mapCIDtoProviderSet map[string]*providerSet) {
	if e.Error != nil {
		p.log.LogAttrs(ctx, slog.LevelWarn, "Fetch datastore entry contains error", slog.String("key", e.Key), slog.String("err", e.Error.Error()))
		return
	}

	// drop expired provider advertisements
	isRecordExpired, rec := p.deleteExpiredRecords(ctx, now, e.Key, e.Value)
	if isRecordExpired {
		return
	}

	// get CID in string form, binary peer ID for lookup
	// while the cid is known in the non-private lookup,
	// it's unknown in the private lookup, so we need to get it too
	cid, binPeerID, err := p.decomposeDatastoreKey(ctx, e.Key)
	if err != nil {
		return
	}

	// get multiaddresses from addrBook
	maddrs := p.addrBook.Addrs(peer.ID(binPeerID))

	// forming the address info object for this provider record
	addrInfo := peer.AddrInfo{
		ID:    peer.ID(binPeerID),
		Addrs: p.cfg.AddressFilter(maddrs),
	}

	// mapCIDtoProviderSet maps each CID to a set of providers.
	// Initialize providerset if the map maps this cid to a nil.
	if mapCIDtoProviderSet[cid] == nil {
		mapCIDtoProviderSet[cid] =
			&providerSet{
				providers: []peer.AddrInfo{},
				set:       make(map[peer.ID]time.Time)}
	}

	// get set of providers, add provider to set.
	providerSetForCID := mapCIDtoProviderSet[cid]
	providerSetForCID.addProvider(addrInfo, rec.expiry)
}
