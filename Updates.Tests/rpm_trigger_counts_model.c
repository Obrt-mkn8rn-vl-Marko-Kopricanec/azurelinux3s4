/* Finite current NAME-index count delivery MODEL; no vendor database. */
void* rpmdbNextIterator(TS *ts);
const char* headerGetString(void *header, int tag);
static unsigned count_model_queries, count_model_database_reads;
static unsigned char count_model_database, count_model_other_database;
void triggerCountModelReset(void) { count_model_queries=count_model_database_reads=0; ran=0; }
unsigned triggerCountModelQueries(void) { return count_model_queries; }
void *rpmtsGetRdb(TS *ts) {
    count_model_database_reads++;
    if(setting("count_db_null")) return NULL;
    if(setting("count_db_alias")) return ts;
    if(setting("count_db_changed") && count_model_database_reads%2==0)
        return &count_model_other_database;
    if(setting("count_db_after_test") && ran) return &count_model_other_database;
    return &count_model_database;
}
int rpmtsGetDBMode(TS *ts) { return setting("count_wrong_mode")?1:0; }
int rpmdbCountPackages(void *database, const char *name) {
    count_model_queries++;
    if(!name) return setting("count_null_positive")?0:-1;
    if(setting("count_negative")) return -1;
    if(setting("count_overflow")) return 32769;
    TS snapshot={0}; int count=0, visited=0; void *header;
    while((header=rpmdbNextIterator(&snapshot))!=NULL) {
        if(++visited>32768) return -1;
        if(!strcmp(headerGetString(header,1000),name)) count++;
    }
    if(setting("count_mismatch") || (setting("count_after_test") && ran)) count++;
    if(setting("count_caller_changed")) ((char *)name)[0]='Z';
    if(getenv("S4_TEST_ROOT")) record("count",count);
    return count;
}
