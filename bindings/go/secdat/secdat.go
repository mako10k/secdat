package secdat

/*
#cgo pkg-config: libsecdat
#include <stdlib.h>
#include "secdat-sdk.h"
*/
import "C"

import (
	"errors"
	"math"
	"unsafe"
)

var ErrCallFailed = errors.New("libsecdat call failed; see stderr for details")

type KeySource int

const (
	KeySourceLocked KeySource = iota
	KeySourceEnvironment
	KeySourceSession
	KeySourceOrphaned
)

func (source KeySource) String() string {
	switch source {
	case KeySourceEnvironment:
		return "environment"
	case KeySourceSession:
		return "session"
	case KeySourceOrphaned:
		return "orphaned"
	default:
		return "locked"
	}
}

type EffectiveSource int

const (
	EffectiveSourceLocked EffectiveSource = iota
	EffectiveSourceEnvironment
	EffectiveSourceLocalSession
	EffectiveSourceInheritedSession
	EffectiveSourceExplicitLock
	EffectiveSourceBlocked
	EffectiveSourceOrphaned
)

func (source EffectiveSource) String() string {
	switch source {
	case EffectiveSourceEnvironment:
		return "environment"
	case EffectiveSourceLocalSession:
		return "local_session"
	case EffectiveSourceInheritedSession:
		return "inherited_session"
	case EffectiveSourceExplicitLock:
		return "explicit_lock"
	case EffectiveSourceBlocked:
		return "blocked"
	case EffectiveSourceOrphaned:
		return "orphaned"
	default:
		return "locked"
	}
}

type RedactionFieldClass int

const (
	RedactionSecretValue RedactionFieldClass = iota
	RedactionSecretDerivedIdentifier
	RedactionNonSecretMetadata
	RedactionCommandArgv
	RedactionPathDomainLabel
	RedactionPublicText
)

func (fieldClass RedactionFieldClass) String() string {
	switch fieldClass {
	case RedactionSecretValue:
		return "secret_value"
	case RedactionSecretDerivedIdentifier:
		return "secret_derived_identifier"
	case RedactionNonSecretMetadata:
		return "non_secret_metadata"
	case RedactionCommandArgv:
		return "command_argv"
	case RedactionPathDomainLabel:
		return "path_domain_label"
	case RedactionPublicText:
		return "public_text"
	default:
		return "unknown"
	}
}

type Options struct {
	Dir    string
	Domain string
	Store  string
}

type ListFilters struct {
	IncludePattern string
	ExcludePattern string
	Safe           bool
	UnsafeStore    bool
	BulkGate       bool
}

type DomainFilters struct {
	Pattern            string
	IncludeAncestors   bool
	IncludeDescendants bool
	IncludeInherited   bool
}

type ExecPlanOptions struct {
	InjectRules       []string
	InjectFiles       []string
	BulkGate          bool
	CommandResolution string
	Argv              []string
}

type StatusSummary struct {
	StoreCount              uint64
	VisibleKeyCount         uint64
	WrappedMasterKeyPresent bool
	KeySource               KeySource
	EffectiveSource         EffectiveSource
	SessionExpiresAt        int64
	RelatedDomainRoot       string
}

type KeyMetadata struct {
	Key             string
	Store           string
	CanonicalKeyref string
	SourceDomain    string
	SourceType      string
	Local           bool
	Inherited       bool
	UnsafeStore     bool
	StorageMode     string
	KeyVisibility   string
	ValueAccess     string
	BulkSelect      string
}

type StoreMetadata struct {
	Name string
}

type DomainMetadata struct {
	Root                    string
	Unlocked                bool
	KeySource               KeySource
	EffectiveSource         EffectiveSource
	SessionExpiresAt        int64
	RemainingSeconds        int64
	RelatedDomainRoot       string
	StoreCount              uint64
	VisibleKeyCount         uint64
	OrphanedDomain          bool
	WrappedMasterKeyPresent bool
}

type RedactionClassification struct {
	FieldClass   RedactionFieldClass
	ClassName    string
	PolicyName   string
	DisplayLabel string
	ValueAllowed bool
}

type RelationRefreshSuggestion struct {
	Severity      string
	RelationID    string
	LeakedRole    string
	RefreshRole   string
	RefreshKeyref string
	Reason        string
}

type cOptions struct {
	raw    C.struct_secdat_sdk_options
	dir    *C.char
	domain *C.char
	store  *C.char
}

type cListFilters struct {
	raw            C.struct_secdat_sdk_list_filters
	includePattern *C.char
	excludePattern *C.char
}

type cDomainFilters struct {
	raw     C.struct_secdat_sdk_domain_filters
	pattern *C.char
}

type cStringArray struct {
	items  []*C.char
	block  unsafe.Pointer
	length int
}

type cExecPlanOptions struct {
	raw               C.struct_secdat_sdk_exec_plan_options
	injectRules       cStringArray
	injectFiles       cStringArray
	commandResolution *C.char
	argv              cStringArray
}

func cStringOrNil(value string) *C.char {
	if value == "" {
		return nil
	}
	return C.CString(value)
}

func newCStringArray(values []string) cStringArray {
	array := cStringArray{}
	if len(values) == 0 {
		return array
	}
	array.block = C.calloc(C.size_t(len(values)), C.size_t(unsafe.Sizeof(uintptr(0))))
	if array.block == nil {
		return array
	}
	array.length = len(values)
	array.items = make([]*C.char, 0, len(values))
	pointers := unsafe.Slice((**C.char)(array.block), len(values))
	for _, value := range values {
		item := C.CString(value)
		array.items = append(array.items, item)
		pointers[len(array.items)-1] = item
	}
	return array
}

func (array *cStringArray) ptr() **C.char {
	if array.block == nil {
		return nil
	}
	return (**C.char)(array.block)
}

func (array *cStringArray) free() {
	for _, item := range array.items {
		C.free(unsafe.Pointer(item))
	}
	C.free(array.block)
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

func newCListFilters(filters ListFilters) cListFilters {
	prepared := cListFilters{}
	prepared.includePattern = cStringOrNil(filters.IncludePattern)
	prepared.excludePattern = cStringOrNil(filters.ExcludePattern)
	prepared.raw.include_pattern = prepared.includePattern
	prepared.raw.exclude_pattern = prepared.excludePattern
	prepared.raw.safe = C.int(boolToInt(filters.Safe))
	prepared.raw.unsafe_store = C.int(boolToInt(filters.UnsafeStore))
	prepared.raw.bulk_gate = C.int(boolToInt(filters.BulkGate))
	return prepared
}

func (filters *cListFilters) free() {
	C.free(unsafe.Pointer(filters.includePattern))
	C.free(unsafe.Pointer(filters.excludePattern))
}

func newCDomainFilters(filters DomainFilters) cDomainFilters {
	prepared := cDomainFilters{}
	prepared.pattern = cStringOrNil(filters.Pattern)
	prepared.raw.pattern = prepared.pattern
	prepared.raw.include_ancestors = C.int(boolToInt(filters.IncludeAncestors))
	prepared.raw.include_descendants = C.int(boolToInt(filters.IncludeDescendants))
	prepared.raw.include_inherited = C.int(boolToInt(filters.IncludeInherited))
	return prepared
}

func (filters *cDomainFilters) free() {
	C.free(unsafe.Pointer(filters.pattern))
}

func newCExecPlanOptions(options ExecPlanOptions) cExecPlanOptions {
	prepared := cExecPlanOptions{}
	prepared.injectRules = newCStringArray(options.InjectRules)
	prepared.injectFiles = newCStringArray(options.InjectFiles)
	prepared.argv = newCStringArray(options.Argv)
	prepared.commandResolution = cStringOrNil(options.CommandResolution)
	prepared.raw.inject_rules = prepared.injectRules.ptr()
	prepared.raw.inject_rule_count = C.size_t(prepared.injectRules.length)
	prepared.raw.inject_files = prepared.injectFiles.ptr()
	prepared.raw.inject_file_count = C.size_t(prepared.injectFiles.length)
	prepared.raw.bulk_gate = C.int(boolToInt(options.BulkGate))
	prepared.raw.command_resolution = prepared.commandResolution
	prepared.raw.argv = prepared.argv.ptr()
	prepared.raw.argv_count = C.size_t(prepared.argv.length)
	return prepared
}

func (options *cExecPlanOptions) free() {
	options.injectRules.free()
	options.injectFiles.free()
	C.free(unsafe.Pointer(options.commandResolution))
	options.argv.free()
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
		StoreCount:              uint64(summary.store_count),
		VisibleKeyCount:         uint64(summary.visible_key_count),
		WrappedMasterKeyPresent: summary.wrapped_master_key_present != 0,
		KeySource:               KeySource(summary.key_source),
		EffectiveSource:         EffectiveSource(summary.effective_source),
		SessionExpiresAt:        int64(summary.session_expires_at),
		RelatedDomainRoot:       C.GoString(&summary.related_domain_root[0]),
	}, nil
}

func ListKeys(options Options, filters ListFilters) ([]KeyMetadata, error) {
	prepared := newCOptions(options)
	defer prepared.free()
	preparedFilters := newCListFilters(filters)
	defer preparedFilters.free()

	var result C.struct_secdat_sdk_key_metadata_list
	if C.secdat_sdk_list_keys(&prepared.raw, &preparedFilters.raw, &result) != 0 {
		return nil, ErrCallFailed
	}
	defer C.secdat_sdk_free(unsafe.Pointer(result.items))

	if result.count == 0 {
		return []KeyMetadata{}, nil
	}

	items := unsafe.Slice(result.items, int(result.count))
	metadata := make([]KeyMetadata, 0, int(result.count))
	for _, item := range items {
		metadata = append(metadata, KeyMetadata{
			Key:             C.GoString(&item.key[0]),
			Store:           C.GoString(&item.store[0]),
			CanonicalKeyref: C.GoString(&item.canonical_keyref[0]),
			SourceDomain:    C.GoString(&item.source_domain[0]),
			SourceType:      C.GoString(&item.source_type[0]),
			Local:           item.local != 0,
			Inherited:       item.inherited != 0,
			UnsafeStore:     item.unsafe_store != 0,
			StorageMode:     C.GoString(&item.storage_mode[0]),
			KeyVisibility:   C.GoString(&item.key_visibility[0]),
			ValueAccess:     C.GoString(&item.value_access[0]),
			BulkSelect:      C.GoString(&item.bulk_select[0]),
		})
	}
	return metadata, nil
}

func ListStores(options Options) ([]StoreMetadata, error) {
	prepared := newCOptions(options)
	defer prepared.free()

	var result C.struct_secdat_sdk_store_metadata_list
	if C.secdat_sdk_list_stores(&prepared.raw, &result) != 0 {
		return nil, ErrCallFailed
	}
	defer C.secdat_sdk_free(unsafe.Pointer(result.items))

	if result.count == 0 {
		return []StoreMetadata{}, nil
	}

	items := unsafe.Slice(result.items, int(result.count))
	metadata := make([]StoreMetadata, 0, int(result.count))
	for _, item := range items {
		metadata = append(metadata, StoreMetadata{Name: C.GoString(&item.name[0])})
	}
	return metadata, nil
}

func ListDomains(options Options, filters DomainFilters) ([]DomainMetadata, error) {
	prepared := newCOptions(options)
	defer prepared.free()
	preparedFilters := newCDomainFilters(filters)
	defer preparedFilters.free()

	var result C.struct_secdat_sdk_domain_metadata_list
	if C.secdat_sdk_list_domains(&prepared.raw, &preparedFilters.raw, &result) != 0 {
		return nil, ErrCallFailed
	}
	defer C.secdat_sdk_free(unsafe.Pointer(result.items))

	if result.count == 0 {
		return []DomainMetadata{}, nil
	}

	items := unsafe.Slice(result.items, int(result.count))
	metadata := make([]DomainMetadata, 0, int(result.count))
	for _, item := range items {
		metadata = append(metadata, DomainMetadata{
			Root:                    C.GoString(&item.root[0]),
			Unlocked:                item.unlocked != 0,
			KeySource:               KeySource(item.key_source),
			EffectiveSource:         EffectiveSource(item.effective_source),
			SessionExpiresAt:        int64(item.session_expires_at),
			RemainingSeconds:        int64(item.remaining_seconds),
			RelatedDomainRoot:       C.GoString(&item.related_domain_root[0]),
			StoreCount:              uint64(item.store_count),
			VisibleKeyCount:         uint64(item.visible_key_count),
			OrphanedDomain:          item.orphaned_domain != 0,
			WrappedMasterKeyPresent: item.wrapped_master_key_present != 0,
		})
	}
	return metadata, nil
}

func ExecPlanJSON(options Options, planOptions ExecPlanOptions) (string, error) {
	prepared := newCOptions(options)
	defer prepared.free()
	preparedPlan := newCExecPlanOptions(planOptions)
	defer preparedPlan.free()

	var jsonOut *C.char
	C.secdat_sdk_exec_plan_json(&prepared.raw, &preparedPlan.raw, &jsonOut)
	if jsonOut == nil {
		return "", ErrCallFailed
	}
	defer C.secdat_sdk_free(unsafe.Pointer(jsonOut))

	return C.GoString(jsonOut), nil
}

func RedactionClassName(fieldClass RedactionFieldClass) (string, error) {
	value := C.secdat_sdk_redaction_class_name(C.enum_secdat_sdk_redaction_field_class(fieldClass))
	if value == nil {
		return "", ErrCallFailed
	}
	return C.GoString(value), nil
}

func RedactionPolicyName(fieldClass RedactionFieldClass) (string, error) {
	value := C.secdat_sdk_redaction_policy_name(C.enum_secdat_sdk_redaction_field_class(fieldClass))
	if value == nil {
		return "", ErrCallFailed
	}
	return C.GoString(value), nil
}

func RedactionDisplayLabel(fieldClass RedactionFieldClass) (string, error) {
	value := C.secdat_sdk_redaction_display_label(C.enum_secdat_sdk_redaction_field_class(fieldClass))
	if value == nil {
		return "", ErrCallFailed
	}
	return C.GoString(value), nil
}

func RedactionValueAllowed(fieldClass RedactionFieldClass) bool {
	return C.secdat_sdk_redaction_value_allowed(C.enum_secdat_sdk_redaction_field_class(fieldClass)) != 0
}

func DescribeRedactionClass(fieldClass RedactionFieldClass) (RedactionClassification, error) {
	var classification C.struct_secdat_sdk_redaction_classification
	if C.secdat_sdk_describe_redaction_class(C.enum_secdat_sdk_redaction_field_class(fieldClass), &classification) != 0 {
		return RedactionClassification{}, ErrCallFailed
	}
	return redactionClassificationFromC(classification), nil
}

func ClassifyExecJSONField(fieldPath string) (RedactionClassification, error) {
	cfieldPath := C.CString(fieldPath)
	defer C.free(unsafe.Pointer(cfieldPath))

	var classification C.struct_secdat_sdk_redaction_classification
	if C.secdat_sdk_classify_exec_json_field(cfieldPath, &classification) != 0 {
		return RedactionClassification{}, ErrCallFailed
	}
	return redactionClassificationFromC(classification), nil
}

func RelationSuggestRefresh(options Options, keyref string) ([]RelationRefreshSuggestion, error) {
	prepared := newCOptions(options)
	defer prepared.free()

	ckeyref := C.CString(keyref)
	defer C.free(unsafe.Pointer(ckeyref))

	var result C.struct_secdat_sdk_relation_refresh_suggestion_list
	if C.secdat_sdk_relation_suggest_refresh(&prepared.raw, ckeyref, &result) != 0 {
		return nil, ErrCallFailed
	}
	defer C.secdat_sdk_free(unsafe.Pointer(result.items))

	if result.count == 0 {
		return []RelationRefreshSuggestion{}, nil
	}

	items := unsafe.Slice(result.items, int(result.count))
	suggestions := make([]RelationRefreshSuggestion, 0, int(result.count))
	for _, item := range items {
		suggestions = append(suggestions, RelationRefreshSuggestion{
			Severity:      C.GoString(item.severity),
			RelationID:    C.GoString(item.relation_id),
			LeakedRole:    C.GoString(item.leaked_role),
			RefreshRole:   C.GoString(item.refresh_role),
			RefreshKeyref: C.GoString(item.refresh_keyref),
			Reason:        C.GoString(item.reason),
		})
	}
	return suggestions, nil
}

func WaitUnlock(options Options, timeoutSeconds int64) error {
	prepared := newCOptions(options)
	defer prepared.free()

	if C.secdat_sdk_wait_unlock(&prepared.raw, C.time_t(timeoutSeconds)) != 0 {
		return ErrCallFailed
	}
	return nil
}

func redactionClassificationFromC(classification C.struct_secdat_sdk_redaction_classification) RedactionClassification {
	return RedactionClassification{
		FieldClass:   RedactionFieldClass(classification.field_class),
		ClassName:    C.GoString(classification.class_name),
		PolicyName:   C.GoString(classification.policy_name),
		DisplayLabel: C.GoString(classification.display_label),
		ValueAllowed: classification.value_allowed != 0,
	}
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
