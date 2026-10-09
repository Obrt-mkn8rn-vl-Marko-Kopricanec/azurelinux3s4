/* Reduced PSM count/branch arithmetic MODEL, not RPM/vendor execution.
 * Immediate iterator cardinality is deliberately NOT supplied or inferred.
 * No DB, header, count query, script, allocation or process is created. */
#include <stdint.h>
int triggerArgumentModel(int immediate,int correction,int target,int source,
        int matched,int marked,int *arg1,int *arg2) {
    *arg1=*arg2=INT32_MIN;
    if ((immediate!=0 && immediate!=1) || (correction!=-1 && correction!=0)
            || target<0 || target>32768 || source<0 || source>32768
            || (matched!=0 && matched!=1) || (marked!=0 && marked!=1)
            || (!immediate && marked)) return -1;
    if (!immediate && source+correction<0) return 0;
    if (!matched || marked) return 0;
    *arg1=target+(immediate?correction:0);
    if (!immediate) *arg2=source+correction;
    return immediate?3:1; /* branch reached; bit2 requires UNKNOWN iterator */
}
