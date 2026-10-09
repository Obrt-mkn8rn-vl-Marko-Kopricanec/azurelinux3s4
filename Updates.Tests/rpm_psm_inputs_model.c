/* Finite source-getter delivery only. No real Header, PSM or source install. */
int rpmteIsSource(void *element) {
    record("element-source", (long)(uintptr_t)element);
    if (!element) return setting("element_source_null_invalid") ? 1 : 0;
    if (setting("element_source_invalid")) return 2;
    if (setting("element_source") || (ran && setting("element_source_changed"))) return 1;
    if ((uintptr_t)element >= 2 && setting("element_source_removed")) return 1;
    return 0;
}
