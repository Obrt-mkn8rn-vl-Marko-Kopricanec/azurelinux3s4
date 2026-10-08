/* Finite public dependency-ABI/failure delivery MODEL, not vendor RPM.
 * Version overlaps delegate to the existing finite rpm_range_model.c.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern void *rpmverParse(const char *);
extern int rpmverOverlap(void *, unsigned, void *, unsigned);
extern void *rpmverFree(void *);
struct dependency_model { int tag; unsigned flags; char *name, *evr; };
static unsigned dependency_allocated, dependency_freed, dependency_compared;
static struct dependency_model *dependency_alias;
static int dependency_fault(const char *name) {
    const char *value = getenv("S4_DEPENDENCY_MODEL_FAULT");
    return value && !strcmp(value, name);
}
unsigned dependencyModelAllocated(void) { return dependency_allocated; }
unsigned dependencyModelFreed(void) { return dependency_freed; }
unsigned dependencyModelCompared(void) { return dependency_compared; }
void dependencyModelReset(void) {
    dependency_allocated = dependency_freed = dependency_compared = 0;
    dependency_alias = NULL;
}
void *rpmdsSingle(int tag, const char *name, const char *evr, unsigned flags) {
    if (dependency_fault("allocate") ||
        (dependency_fault("second-allocate") && dependency_allocated % 2)) return NULL;
    if (dependency_fault("alias") && dependency_alias) return dependency_alias;
    struct dependency_model *value = calloc(1, sizeof(*value));
    if (!value) return NULL;
    value->tag = tag; value->flags = flags; value->name = strdup(name); value->evr = strdup(evr);
    dependency_allocated++;
    if (dependency_fault("alias")) dependency_alias = value;
    return value;
}
int rpmdsCount(void *p) { return dependency_fault("count") ? 2 : 1; }
int rpmdsIx(void *p) { return dependency_fault("index") ? -1 : 0; }
int rpmdsTagN(void *p) { return dependency_fault("tag") ? 1049 : ((struct dependency_model *)p)->tag; }
const char *rpmdsN(void *p) { return dependency_fault("name") ? "changed" : ((struct dependency_model *)p)->name; }
const char *rpmdsEVR(void *p) { return dependency_fault("evr") ? "changed" : ((struct dependency_model *)p)->evr; }
unsigned rpmdsFlags(void *p) { return dependency_fault("flags") ? 42 : ((struct dependency_model *)p)->flags; }
void *rpmdsFree(void *p) {
    if (p) {
        struct dependency_model *value = p;
        free(value->name); free(value->evr); free(value); dependency_freed++;
    }
    return dependency_fault("free") ? (void *)1 : NULL;
}
int rpmdsCompare(void *left, void *right) {
    struct dependency_model *a = left, *b = right;
    dependency_compared++;
    if (dependency_fault("positive")) return 1;
    if (dependency_fault("zero")) return 0;
    if (dependency_fault("invalid")) return 42;
    if (dependency_fault("asymmetric")) return dependency_compared % 2;
    if (dependency_fault("changed")) { a->flags ^= 2; return 1; }
    if (strcmp(a->name, b->name)) return 0;
    if (!(a->flags & 15) || !(b->flags & 15) || !*a->evr || !*b->evr) return 1;
    void *av = rpmverParse(a->evr), *bv = rpmverParse(b->evr);
    int result = av && bv ? rpmverOverlap(av, a->flags, bv, b->flags) : 42;
    rpmverFree(av); rpmverFree(bv);
    return result;
}
