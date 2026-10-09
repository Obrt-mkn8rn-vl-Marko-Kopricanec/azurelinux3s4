/* Finite mask-transition/policy delivery. No cryptography or vendor PSM. */
unsigned rpmtsVSFlags(void *ts) {
    record("verification-header-flags", ts != NULL);
    return ts && setting("verification_header_relaxed") ? 256 : 0;
}
unsigned rpmtsVfyFlags(void *ts) {
    record("verification-package-flags", ts != NULL);
    return ts && setting("verification_package_relaxed") ? 256 : 0;
}
int rpmtsVfyLevel(void *ts) {
    record("verification-required-types", ts != NULL);
    if (!ts) return setting("verification_policy_null_invalid") ? 3 : 0;
    return setting("verification_level_relaxed") ? 1 : 3;
}
int rpmteVerified(void *element) {
    record("element-verified", (long)(uintptr_t)element);
    if (!element) return setting("verification_null_invalid") ? 3 : 0;
    if (setting("verification_invalid")) return 4;
    if (!(ran || setting("verification_sample_post")))
        return setting("verification_prior") ? 3 : (1 << 30);
    if ((uintptr_t)element >= 2)
        return setting("verification_removed") ? 3 : (1 << 30);
    if (setting("verification_digest_only")) return 1;
    if (setting("verification_signature_only")) return 2;
    if (setting("verification_none")) return 0;
    if (setting("verification_unattempted")) return (1 << 30);
    return 3;
}
