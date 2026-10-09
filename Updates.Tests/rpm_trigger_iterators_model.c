/* Finite NAME-index lookup/traversal delivery MODEL, not a vendor database. */
void* rpmdbNextIterator(TS *ts);
uint32_t rpmdbGetIteratorOffset(TS *ts);
const char* headerGetString(void *header,int tag);
static struct IteratorModel {
    TS snapshots[32768], current;
    unsigned offsets[32768], count, cursor, offset;
} *iterator_model_active;
static unsigned iterator_model_acquired, iterator_model_retired, iterator_model_null_frees;
int triggerIteratorModelOwns(void *p) { return p && p==iterator_model_active; }
void triggerIteratorModelReset(void) {
    if(iterator_model_active) abort();
    iterator_model_acquired=iterator_model_retired=iterator_model_null_frees=0; ran=0;
}
unsigned triggerIteratorModelAcquired(void) { return iterator_model_acquired; }
unsigned triggerIteratorModelRetired(void) { return iterator_model_retired; }
unsigned triggerIteratorModelNullFrees(void) { return iterator_model_null_frees; }
void *rpmdbInitIterator(void *db,int tag,const char *name,size_t length) {
    if(tag!=1000 || !name || length || !db || iterator_model_active) abort();
    struct IteratorModel *mi=calloc(1,sizeof(*mi)); TS scan={0}; void *header;
    unsigned visited=0;
    while((header=rpmdbNextIterator(&scan))!=NULL) {
        if(++visited>32768) abort();
        if(strcmp(headerGetString(header,1000),name)) continue;
        mi->snapshots[mi->count]=*(TS *)header;
        mi->offsets[mi->count++]=rpmdbGetIteratorOffset(&scan);
    }
    if(!mi->count) { free(mi); return NULL; }
    iterator_model_active=mi; iterator_model_acquired++;
    if(getenv("S4_TEST_ROOT")) record("name-iterator-open",mi->count);
    return mi;
}
int rpmdbGetIteratorCount(void *p) {
    if(!p) return setting("iterator_null_count")?1:0;
    if(!triggerIteratorModelOwns(p)) abort();
    return iterator_model_active->count + (setting("iterator_count_mismatch") || (ran && setting("iterator_after_test")));
}
void *triggerIteratorModelNext(void *p) {
    struct IteratorModel *mi=p;
    if(mi->cursor>=mi->count || setting("iterator_early_end")) return NULL;
    mi->current=mi->snapshots[mi->cursor];mi->offset=mi->offsets[mi->cursor++];
    return &mi->current;
}
unsigned triggerIteratorModelOffset(void *p) {
    struct IteratorModel *mi=p;
    return setting("iterator_foreign")?4294967295U:mi->offset;
}
void *rpmdbNextIterator(TS *p) {
    if(!p) return NULL;
    return triggerIteratorModelOwns(p)?triggerIteratorModelNext(p):iteratorModelOldNext(p);
}
unsigned rpmdbGetIteratorOffset(TS *p) {
    return triggerIteratorModelOwns(p)?triggerIteratorModelOffset(p):iteratorModelOldOffset(p);
}
void *rpmdbFreeIterator(void *p) {
    if(!p) { iterator_model_null_frees++; return NULL; }
    if(!triggerIteratorModelOwns(p)) return iteratorModelOldFree(p);
    iterator_model_retired++;free(iterator_model_active);iterator_model_active=NULL;
    if(getenv("S4_TEST_ROOT")) record("name-iterator-close",1);
    return setting("iterator_free_failure")?p:NULL;
}
