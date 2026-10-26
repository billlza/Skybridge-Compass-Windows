#include "SkyBridgeALACDecoder.h"

/* These describe this exact C compilation, rather than managed assumptions
 * about pointer width, padding or an OS codec's version. All memory stays owned
 * and freed by the same native module. */
unsigned sbalac_bridge_abi_version(void) { return 1; }
size_t sbalac_source_description_size(void) { return sizeof(SBALACSourceDescription); }
size_t sbalac_control_size(void) { return sizeof(SBALACControl); }
size_t sbalac_result_size(void) { return sizeof(SBALACResult); }
