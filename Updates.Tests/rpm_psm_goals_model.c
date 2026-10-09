/* Finite formula/control-flow MODEL, not RPM or its pkgGoal ABI. */
enum model_goal { MODEL_INSTALL, MODEL_PRETRANS, MODEL_ERASE, MODEL_VERIFY, MODEL_POSTTRANS };

int model_psm_goal(int goal, int count, int target, const int *removed_links,
                   int links, int sum_links_fault, int *argument, int *correction)
{
    int update = 0;
    if (goal < MODEL_INSTALL || goal > MODEL_POSTTRANS || count < 0 || count > 32768 || links < 0)
        return -1;
    switch (goal) {
    case MODEL_INSTALL:
    case MODEL_PRETRANS:
        *argument = count + 1;
        *correction = 0;
        break;
    case MODEL_ERASE:
        *argument = count - 1;
        *correction = -1;
        break;
    case MODEL_VERIFY:
    case MODEL_POSTTRANS:
        for (int i = 0; i < links; i++) {
            if (removed_links[i] == target) {
                update++;
                if (!sum_links_fault) break;
            }
        }
        *argument = count + update;
        *correction = 0;
        break;
    }
    return 0;
}
