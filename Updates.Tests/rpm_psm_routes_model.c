/* Finite source-control-flow model only; no RPM, files or script execution. */
int model_psm_route(int type, int phase, int body, int program, int fault,
                    int *goal, int *open_attempt)
{
    if ((type != 1 && type != 2) || phase < 0 || phase > 2 ||
        body < 0 || body > 1 || program < 0 || program > 1)
        return -1;
    if (phase == 0) {
        *goal = type;
        *open_attempt = 1;
        return 0;
    }
    *goal = phase == 1 ? 1151 : 1152;
    /* runTransScripts filters TR_ADDED before rpmteProcess's presence test. */
    *open_attempt = type == 1 && (fault ? body && program : body || program);
    return 0;
}
