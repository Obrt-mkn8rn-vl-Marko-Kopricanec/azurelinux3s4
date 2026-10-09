/* Finite borrowed-DS iterator delivery MODEL, not vendor/database execution. */
static unsigned iteration_init_calls, iteration_next_calls, iteration_pass;
static int iteration_fault(const char *name) {
    const char *v=getenv("S4_HEADER_ITERATION_MODEL_FAULT"); return v && !strcmp(v,name);
}
void headerIterationModelReset(void) { iteration_init_calls=iteration_next_calls=iteration_pass=0; }
unsigned headerIterationModelInitCalls(void) { return iteration_init_calls; }
unsigned headerIterationModelNextCalls(void) { return iteration_next_calls; }
void *rpmdsInit(void *p) {
    iteration_init_calls++; struct header_ds *d=known_ds(p);
    if(!p) return iteration_fault("null-init")?(void *)1:NULL;
    if(!d) return NULL;
    iteration_pass++;
    if(iteration_fault("init-null")) return NULL;
    if(iteration_fault("init-header")) return d->header;
    if(iteration_fault("init-caller")) return d->header->caller;
    if(iteration_fault("init-prior") && d->next) return d->next;
    d->ix=iteration_fault("init-index")?0:-1;
    return d;
}
int rpmdsNext(void *p) {
    iteration_next_calls++; struct header_ds *d=known_ds(p);
    if(!p) return iteration_fault("null-next")?0:-1;
    if(!d) return -1;
    if(iteration_fault("early-end")) { d->ix=-1; return -1; }
    if(iteration_fault("repeat")) { d->ix=0; return 0; }
    d->ix++;
    if(iteration_fault("skip") || (iteration_fault("second-skip") && iteration_pass==2)) d->ix++;
    if(d->ix<d->count) {
        int index=d->ix;
        if(iteration_fault("row-flags")) ((unsigned char *)value(d,1068))[0]^=1;
        if(iteration_fault("receipt-index")) d->ix=-1;
        return index;
    }
    if(iteration_fault("end-positive")) return d->ix;
    d->ix=-1;
    return iteration_fault("end-wrong")?-2:-1;
}
