/* Reduced conditional PSM control-flow MODEL; no RPM, DB or script operation. */
#include <stdint.h>

int triggerWalkModel(int count, const int *names, const int *slots,
    const uint32_t *senses, int sources, const int *source_names,
    const int *order, const int *matches, uint32_t phase, int correction,
    int target_count, int *calls, int *marked_result)
{
    unsigned marked = 0;
    int total = 0;
    if (count < 0 || count > 16 || sources < 0 || sources > 8)
        return -1;
    for (int i = 0; i < count; i++) {
        if (slots[i] < 0 || slots[i] > 15) return -1;
        if (marked & (1U << slots[i])) continue;
        int cardinality = 0;
        for (int s = 0; s < sources; s++) cardinality += source_names[s] == names[i];
        for (int s = 0; s < sources; s++) {
            int source = order[s];
            if (source < 0 || source >= sources) return -1;
            if (source_names[source] != names[i]) continue;
            for (int j = 0; j < count; j++) {
                if (!(senses[j] & phase) || names[j] != source_names[source]
                    || !matches[source * count + j]) continue;
                if (!(marked & (1U << slots[j]))) {
                    if (total >= 128) return -1;
                    int *call = calls + 5 * total++;
                    call[0] = i; call[1] = source; call[2] = slots[j];
                    call[3] = target_count + correction; call[4] = cardinality;
                    marked |= 1U << slots[j];
                }
#ifndef WALK_OMIT_FIRST_BREAK
                break;
#endif
            }
        }
    }
    *marked_result = (int)marked;
    return total;
}
