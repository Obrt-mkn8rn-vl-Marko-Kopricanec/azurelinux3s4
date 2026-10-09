/* Finite failure-getter delivery. No real Header, failure propagation or PSM. */
int rpmteFailed(void *element) {
    record("element-failed", (long)(uintptr_t)element);
    if (!element) return setting("element_failure_null_invalid") ? 0 : -1;
    if (setting("element_failure_invalid")) return -1;
    if (setting("element_failure") || (ran && setting("element_failure_changed"))) return 1;
    if ((uintptr_t)element >= 2 && setting("element_failure_removed")) return 2;
    return 0;
}
