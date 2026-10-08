/* Finite ABI/error-delivery MODEL, not RPM semantics or an authenticated library.
 * Only the named test vectors and ordinary small integer inputs are supported.
 */
#include <stdlib.h>
#include <string.h>

int rpmvercmp(const char *left, const char *right)
{
    const char *fault = getenv("S4_VERSION_MODEL_FAULT");
    if (fault && !strcmp(fault, "positive")) return 1;
    if (fault && !strcmp(fault, "zero")) return 0;
    if (fault && !strcmp(fault, "invalid")) return 42;
    if (!strcmp(left, right)) return 0;
    struct vector { const char *left; const char *right; int result; };
    const struct vector vectors[] = {
        {"1.10", "1.9", 1}, {"1.01", "1.1", 0},
        {"1.0~rc1", "1.0", -1}, {"1.0^git", "1.0", 1},
        {"1.0^git", "1.0.1", -1}, {"2.azl3", "1.azl3", 1},
        {"1.0", "2.0", -1}, {"1.0", "0.9", 1},
        {"1", "1.0", -1}, {"1.0", "1.00", 0},
    };
    for (unsigned i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i) {
        if (!strcmp(left, vectors[i].left) && !strcmp(right, vectors[i].right)) return vectors[i].result;
        if (!strcmp(right, vectors[i].left) && !strcmp(left, vectors[i].right)) return -vectors[i].result;
    }
    char *first_end, *second_end;
    unsigned long first = strtoul(left, &first_end, 10);
    unsigned long second = strtoul(right, &second_end, 10);
    if (*left && *right && !*first_end && !*second_end)
        return (first > second) - (first < second);
    return 42;
}
