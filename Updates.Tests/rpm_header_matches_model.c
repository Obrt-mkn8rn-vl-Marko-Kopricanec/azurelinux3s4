/* Finite Header-query/ownership failure delivery, NOT vendor RPM matching.
 * Uses existing private Header and dependency models, retaining raw positions. */
static unsigned header_match_calls;
static int match_fault(const char *name) {
    const char *v=getenv("S4_HEADER_MATCH_MODEL_FAULT");return v && !strcmp(v,name);
}
unsigned headerMatchModelCalls(void) { return header_match_calls; }
void headerMatchModelReset(void) { header_match_calls=0; }
void *rpmdsSingle(int tag,const char *name,const char *evr,unsigned flags) {
    if(headers) {
        if(match_fault("request-allocate")) return NULL;
        if(match_fault("request-header")) return headers;
        if(match_fault("request-caller")) return headers->caller;
        if(match_fault("request-dependency") && sets) return sets;
        if(match_fault("request-name")) return (void *)name;
        if(match_fault("request-evr")) return (void *)evr;
        if(match_fault("argument-name-changed")) ((char *)name)[0]^=1;
        if(match_fault("argument-evr-changed")) ((char *)evr)[0]^=1;
    }
    return originalDsSingle(tag,name,evr,flags);
}
int rpmdsAnyMatchesDep(void *p,void *request,int nopromote) {
    struct header_model *h=known_header(p);header_match_calls++;
    if(!h || !request || nopromote!=1) return 42;
    if(match_fault("positive")) return 1;
    if(match_fault("zero")) return 0;
    if(match_fault("invalid")) return 42;
    if(match_fault("alternating")) return header_match_calls%2;
    if(match_fault("request-changed")) ((struct dependency_model *)request)->flags^=2;
    if(match_fault("header-changed") && header_match_calls%2) {
        const unsigned char *f=entry(h,1112);
        if(f) h->data[8+16*number(h->data)+number(f+8)+3]^=2;
    }
    const unsigned char *e=entry(h,1047);if(!e)return 0;
    struct header_ds d={h,1047,(int)number(e+12),0,NULL};
    for(int i=0;i<d.count;i++) {
        d.ix=i;
        struct dependency_model provide={1047,number(value(&d,1112)),(char *)value(&d,1047),(char *)value(&d,1113)};
        if(rpmdsCompare(&provide,request)) return 1;
    }
    return 0;
}
