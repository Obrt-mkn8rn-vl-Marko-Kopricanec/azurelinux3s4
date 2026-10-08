/* Finite import/export/dependency readback and failure delivery MODEL.
 * It preserves fixture bytes, not RPM region/extension semantics or trust.
 * Original API names below are renamed only in the private C delivery.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
struct header_model { unsigned size; unsigned char *data; struct header_model *next; };
struct header_ds { struct header_model *header; int tag, count, ix; struct header_ds *next; };
static struct header_model *headers;
static struct header_ds *sets;
static unsigned imported, retired, ds_created, ds_retired;
static int header_fault(const char *name) {
    const char *v=getenv("S4_HEADER_MODEL_FAULT"); return v && !strcmp(v,name);
}
unsigned headerModelImported(void) { return imported; }
unsigned headerModelRetired(void) { return retired; }
unsigned headerModelDsCreated(void) { return ds_created; }
unsigned headerModelDsRetired(void) { return ds_retired; }
void headerModelReset(void) { imported=retired=ds_created=ds_retired=0; }
static struct header_model *known_header(void *p) {
    for(struct header_model *h=headers;h;h=h->next) if(h==p) return h; return NULL;
}
static struct header_ds *known_ds(void *p) {
    for(struct header_ds *d=sets;d;d=d->next) if(d==p) return d; return NULL;
}
static unsigned number(const unsigned char *p) { uint32_t n; memcpy(&n,p,4); return ntohl(n); }
static const unsigned char *entry(struct header_model *h,int tag) {
    unsigned count=number(h->data);
    for(unsigned i=0;i<count;i++) if(number(h->data+8+16*i)==(unsigned)tag) return h->data+8+16*i;
    return NULL;
}
static const unsigned char *value(struct header_ds *d,int tag) {
    const unsigned char *e=entry(d->header,tag); if(!e) return NULL;
    const unsigned char *p=d->header->data+8+16*number(d->header->data)+number(e+8);
    if(number(e+4)==4) return p+4*d->ix;
    for(int i=0;i<d->ix;i++) p+=strlen((const char *)p)+1;
    return p;
}
void *headerImport(void *blob,unsigned size,unsigned flags) {
    if(header_fault("import") || (header_fault("later-import") && imported)) return NULL;
    if(header_fault("import-buffer")) return blob;
    if(flags!=1 || size<8 || 8+16*number(blob)+number((unsigned char *)blob+4)!=size) return NULL;
    struct header_model *h=calloc(1,sizeof(*h)); h->size=size;h->data=malloc(size);memcpy(h->data,blob,size);
    h->next=headers;headers=h;imported++;
    if(header_fault("caller-change")) ((unsigned char *)blob)[size-1]^=1;
    return h;
}
void *headerExport(void *p,unsigned *size) {
    struct header_model *h=known_header(p); if(!h) return originalHeaderExport(p,size);
    if(header_fault("export-alias")) return h;
    if(header_fault("export")) return NULL;
    *size=h->size+(header_fault("export-size")?1:0);
    unsigned char *b=malloc(*size);memcpy(b,h->data,h->size);
    if(header_fault("export-bytes")) b[h->size-1]^=1;
    return b;
}
void *headerFree(void *p) {
    struct header_model *h=known_header(p);if(!h) return originalHeaderFree(p);
    struct header_model **i=&headers;while(*i!=h)i=&(*i)->next;*i=h->next;
    free(h->data);free(h);retired++;return header_fault("header-free")?(void *)1:NULL;
}
int headerIsEntry(void *p,int tag) {
    struct header_model *h=known_header(p);if(!h) return originalHeaderIsEntry(p,tag);
    return header_fault("presence")?42:entry(h,tag)!=NULL;
}
void *rpmdsNew(void *p,int tag,int flags) {
    struct header_model *h=known_header(p);if(!h || flags) return NULL;
    const unsigned char *e=entry(h,tag);if(!e || header_fault("ds-new")) return NULL;
    if(header_fault("header-alias")) return h;
    if(header_fault("ds-alias") && sets) return sets;
    struct header_ds *d=calloc(1,sizeof(*d));d->header=h;d->tag=tag;d->ix=-1;d->count=number(e+12);
    d->next=sets;sets=d;ds_created++;return d;
}
int rpmdsSetIx(void *p,int ix) { struct header_ds *d=known_ds(p);if(!d)return -1;int old=d->ix;d->ix=ix;return header_fault("set-index")?42:old; }
int rpmdsCount(void *p) { struct header_ds *d=known_ds(p);return d?(header_fault("count")?d->count+1:d->count):originalDsCount(p); }
int rpmdsIx(void *p) { struct header_ds *d=known_ds(p);return d?(header_fault("index")?-1:d->ix):originalDsIx(p); }
int rpmdsTagN(void *p) { struct header_ds *d=known_ds(p);return d?(header_fault("tag")?1049:d->tag):originalDsTagN(p); }
const char *rpmdsN(void *p) { struct header_ds *d=known_ds(p);return d?(header_fault("name")?"changed":(const char *)value(d,d->tag)):originalDsN(p); }
const char *rpmdsEVR(void *p) { struct header_ds *d=known_ds(p);return d?(header_fault("evr")?"changed":(const char *)value(d,d->tag==1047?1113:1067)):originalDsEVR(p); }
unsigned rpmdsFlags(void *p) { struct header_ds *d=known_ds(p);return d?(header_fault("flags")?42:number(value(d,d->tag==1047?1112:1068))):originalDsFlags(p); }
int rpmdsTi(void *p) { struct header_ds *d=known_ds(p);return !d||header_fault("script-index")?-1:(int)number(value(d,1069)); }
void *rpmdsFree(void *p) {
    struct header_ds *d=known_ds(p);if(!d)return originalDsFree(p);
    struct header_ds **i=&sets;while(*i!=d)i=&(*i)->next;*i=d->next;free(d);ds_retired++;
    return header_fault("ds-free")?(void *)1:NULL;
}
