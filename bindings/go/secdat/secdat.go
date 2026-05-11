package secdat

/*
#cgo CFLAGS: -I../../../src
#cgo LDFLAGS: -L../../../src/.libs -lsecdat
#include <stdlib.h>
#include "../../../src/secdat-sdk.h"
*/
import "C"

import (
	"errors"
	"math"
	"unsafe"
)

var ErrCallFailed = errors.New("libsecdat call failed; see stderr for details")

type Options struct {
	Dir    string
	Domain string
	Store  string
}

type StatusSummary struct {
	StoreCount             uint64
	VisibleKeyCount        uint64
	WrappedMasterKeyPresent bool
	KeySource              int
	EffectiveSource        int
	SessionExpiresAt       int64
	RelatedDomainRoot      string
}

type cOptions struct {
	raw    C.struct_secdat_sdk_options
	dir    *C.char
	domain *C.char
	store  *C.char
}

func cStringOrNil(value string) *C.char {
	if value == "" {
		return nil
	}
	return C.CString(value)
}

func newCOptions(options Options) cOptions {
	prepared := cOptions{}
	prepared.dir = cStringOrNil(options.Dir)
	prepared.domain = cStringOrNil(options.Domain)
	prepared.store = cStringOrNil(options.Store)
	prepared.raw.dir = prepared.dir
	prepared.raw.domain = prepared.domain
	prepared.raw.store = prepared.store
	return prepared
}

func (options *cOptions) free() {
	C.free(unsafe.Pointer(options.dir))
	C.free(unsafe.Pointer(options.domain))
	C.free(unsafe.Pointer(options.store))
}

func Get(options Options, keyref string) ([]byte, bool, error) {
	prepared := newCOptions(options)
	defer prepared.free()

	ckeyref := C.CString(keyref)
	defer C.free(unsafe.Pointer(ckeyref))

	var value *C.uchar
	var valueLength C.size_t
	var unsafeStore C.int

	if C.secdat_sdk_get(&prepared.raw, ckeyref, &value, &valueLength, &unsafeStore) != 0 {
		return nil, false, ErrCallFailed
	}
	defer C.secdat_sdk_free(unsafe.Pointer(value))

	if uint64(valueLength) > math.MaxInt32 {
		return nil, false, errors.New("secret too large for GoBytes")
	}

	return C.GoBytes(unsafe.Pointer(value), C.int(valueLength)), unsafeStore != 0, nil
}

func Set(options Options, keyref string, value []byte, unsafeStore bool) error {
	prepared := newCOptions(options)
	defer prepared.free()

	ckeyref := C.CString(keyref)
	defer C.free(unsafe.Pointer(ckeyref))

	var payload *C.uchar
	if len(value) > 0 {
		payload = (*C.uchar)(C.CBytes(value))
		defer C.free(unsafe.Pointer(payload))
	}

	if C.secdat_sdk_set(&prepared.raw, ckeyref, payload, C.size_t(len(value)), C.int(boolToInt(unsafeStore))) != 0 {
		return ErrCallFailed
	}
	return nil
}

func Remove(options Options, keyref string, ignoreMissing bool) error {
	prepared := newCOptions(options)
	defer prepared.free()

	ckeyref := C.CString(keyref)
	defer C.free(unsafe.Pointer(ckeyref))

	if C.secdat_sdk_rm(&prepared.raw, ckeyref, C.int(boolToInt(ignoreMissing))) != 0 {
		return ErrCallFailed
	}
	return nil
}

func Move(options Options, sourceKeyref string, destinationKeyref string) error {
	prepared := newCOptions(options)
	defer prepared.free()

	csource := C.CString(sourceKeyref)
	defer C.free(unsafe.Pointer(csource))
	cdestination := C.CString(destinationKeyref)
	defer C.free(unsafe.Pointer(cdestination))

	if C.secdat_sdk_mv(&prepared.raw, csource, cdestination) != 0 {
		return ErrCallFailed
	}
	return nil
}

func Copy(options Options, sourceKeyref string, destinationKeyref string) error {
	prepared := newCOptions(options)
	defer prepared.free()

	csource := C.CString(sourceKeyref)
	defer C.free(unsafe.Pointer(csource))
	cdestination := C.CString(destinationKeyref)
	defer C.free(unsafe.Pointer(cdestination))

	if C.secdat_sdk_cp(&prepared.raw, csource, cdestination) != 0 {
		return ErrCallFailed
	}
	return nil
}

func Mask(options Options, keyref string) error {
	prepared := newCOptions(options)
	defer prepared.free()

	ckeyref := C.CString(keyref)
	defer C.free(unsafe.Pointer(ckeyref))

	if C.secdat_sdk_mask(&prepared.raw, ckeyref) != 0 {
		return ErrCallFailed
	}
	return nil
}

func Unmask(options Options, keyref string) error {
	prepared := newCOptions(options)
	defer prepared.free()

	ckeyref := C.CString(keyref)
	defer C.free(unsafe.Pointer(ckeyref))

	if C.secdat_sdk_unmask(&prepared.raw, ckeyref) != 0 {
		return ErrCallFailed
	}
	return nil
}

func Unlock(options Options) error {
	prepared := newCOptions(options)
	defer prepared.free()

	if C.secdat_sdk_unlock(&prepared.raw) != 0 {
		return ErrCallFailed
	}
	return nil
}

func Lock(options Options) error {
	prepared := newCOptions(options)
	defer prepared.free()

	if C.secdat_sdk_lock(&prepared.raw) != 0 {
		return ErrCallFailed
	}
	return nil
}

func Exists(options Options, keyref string) (bool, error) {
	prepared := newCOptions(options)
	defer prepared.free()

	ckeyref := C.CString(keyref)
	defer C.free(unsafe.Pointer(ckeyref))

	var exists C.int
	if C.secdat_sdk_exists(&prepared.raw, ckeyref, &exists) != 0 {
		return false, ErrCallFailed
	}
	return exists != 0, nil
}

func CollectStatus(options Options) (StatusSummary, error) {
	prepared := newCOptions(options)
	defer prepared.free()

	var summary C.struct_secdat_sdk_status_summary
	if C.secdat_sdk_collect_status(&prepared.raw, &summary) != 0 {
		return StatusSummary{}, ErrCallFailed
	}

	return StatusSummary{
		StoreCount:             uint64(summary.store_count),
		VisibleKeyCount:        uint64(summary.visible_key_count),
		WrappedMasterKeyPresent: summary.wrapped_master_key_present != 0,
		KeySource:              int(summary.key_source),
		EffectiveSource:        int(summary.effective_source),
		SessionExpiresAt:       int64(summary.session_expires_at),
		RelatedDomainRoot:      C.GoString(&summary.related_domain_root[0]),
	}, nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}