/* Finite public-ABI/error delivery MODEL, not a vendor RPM implementation.
 * Component ordering delegates to rpm_version_model.c's bounded vector model.
 */
#include <stdlib.h>
#include <string.h>

extern int rpmvercmp(const char *, const char *);
struct range_model { char *e, *v, *r; char data[]; };
static unsigned range_allocated, range_freed, range_overlaps;
static struct range_model *range_alias;
static int range_fault(const char *name) {
    const char *value = getenv("S4_RANGE_MODEL_FAULT");
    return value && !strcmp(value, name);
}
unsigned rangeModelAllocated(void) { return range_allocated; }
unsigned rangeModelFreed(void) { return range_freed; }
unsigned rangeModelOverlaps(void) { return range_overlaps; }
void rangeModelReset(void) { range_allocated=range_freed=range_overlaps=0;range_alias=NULL; }
void *rpmverParse(const char *input) {
    if(!input || !*input || range_fault("parse") || (range_fault("second-parse") && range_allocated%2)) return NULL;
    if(range_fault("alias") && range_alias) return range_alias;
    struct range_model *value = calloc(1, sizeof(*value)+strlen(input)+1);
    if(!value) return NULL;
    strcpy(value->data,input); value->v=value->data;
    char *colon=strchr(value->data,':');
    if(colon) { *colon=0;value->e=value->data;value->v=colon+1; }
    char *dash=strrchr(value->v,'-');
    if(dash) { *dash=0;value->r=dash+1; }
    range_allocated++;if(range_fault("alias")) range_alias=value;return value;
}
const char *rpmverE(void *p) { return ((struct range_model *)p)->e; }
const char *rpmverV(void *p) { return range_fault("fields") ? "changed" : ((struct range_model *)p)->v; }
const char *rpmverR(void *p) { return ((struct range_model *)p)->r; }
void *rpmverFree(void *p) {
    if(p) { free(p);range_freed++; }
    return range_fault("free") ? (void *)1 : NULL;
}
int rpmverOverlap(void *first,unsigned f1,void *second,unsigned f2) {
    range_overlaps++;
    if(range_fault("positive")) return 1;
    if(range_fault("zero")) return 0;
    if(range_fault("invalid")) return 42;
    if(range_fault("asymmetric")) return range_overlaps%2;
    struct range_model *a=first,*b=second;
    int order=0;
    if(a->e && b->e) order=rpmvercmp(a->e,b->e);
    else if(a->e && strtoul(a->e,NULL,10)) order=1;
    else if(b->e && strtoul(b->e,NULL,10)) order=-1;
    if(order==42) return 42;
    if(!order) {
        order=rpmvercmp(a->v,b->v);if(order==42) return 42;
        if(!order) {
            if(a->r && b->r) { order=rpmvercmp(a->r,b->r);if(order==42) return 42; }
            else if((a->r && (f2&8)) || (b->r && (f1&8))) return 1;
        }
    }
    return (order<0 && ((f1&4)||(f2&2))) ||
           (order>0 && ((f1&2)||(f2&4))) ||
           (!order && (((f1&8)&&(f2&8)) || ((f1&2)&&(f2&2)) || ((f1&4)&&(f2&4))));
}
