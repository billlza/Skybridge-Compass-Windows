#include "SkyBridgeFLACDecoder.h"

// The managed boundary checks native layouts before creating a decoder. This is
// independent of libFLAC's version: the bridge has its own ABI contract.
uint32_t sbflac_bridge_abi_version(void) { return 1; }
size_t sbflac_source_description_size(void) { return sizeof(SBFLACSourceDescription); }
size_t sbflac_read_access_size(void) { return sizeof(SBFLACReadAccess); }
size_t sbflac_result_size(void) { return sizeof(SBFLACResult); }
