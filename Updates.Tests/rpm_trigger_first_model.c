/* Reduced PSM pair-first control-flow MODEL, not vendor handleOneTrigger.
 * Package NAME equality and captured Header result are already inputs.
 * No database, package counts, scripts, or process execution occurs here. */
#include <stdint.h>
void triggerFirstModel(unsigned count,const uint32_t *positions,
        const uint32_t *flags,const uint32_t *slots,const int *matches,
        uint32_t phase,uint32_t marked,unsigned use_mark,unsigned omit_break,
        uint32_t *position,uint32_t *slot,unsigned *enter) {
    *position=*slot=UINT32_MAX;*enter=0;
    for(unsigned i=0;i<count;i++) {
        if(!(flags[i]&phase)) continue;
        if(!matches[i]) continue;
        *position=positions[i];*slot=slots[i];
        *enter=!use_mark || marked!=slots[i];
        if(!omit_break) break;
    }
}
