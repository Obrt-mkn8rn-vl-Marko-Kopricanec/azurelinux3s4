/* Borrowed TE links for the finite TEST delivery. No vendor DB/PSM execution. */
void *rpmteDependsOn(void *element) {
    if (!element) abort(); /* Pinned getter is not NULL-safe. */
    record("element-dependency", (long)(uintptr_t)element);
    if (setting("element_foreign_dependency")) return (void *)(uintptr_t)99999;
    if (ran && setting("element_changed_dependency")) return NULL;
    if ((uintptr_t)element >= 2) {
        if (setting("element_removed_dependency")) return element;
        if (setting("element_unlinked_removal")) return NULL;
        return (void *)(uintptr_t)1;
    }
    return setting("element_incoming_dependency") ? element : NULL;
}
