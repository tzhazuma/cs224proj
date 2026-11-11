destroyPresentationContextList(LST_HEAD ** l)
{
    PRV_PRESENTATIONCONTEXTITEM
    * prvCtx;
    DUL_SUBITEM
        * subItem;

    if (*l == NULL)
        return;

    prvCtx = (PRV_PRESENTATIONCONTEXTITEM*)LST_Dequeue(l);
    while (prvCtx != NULL) {
        subItem = (DUL_SUBITEM*)LST_Dequeue(&prvCtx->transferSyntaxList);
        while (subItem != NULL) {
            free(subItem);
            subItem = (DUL_SUBITEM*)LST_Dequeue(&prvCtx->transferSyntaxList);
        }
        LST_Destroy(&prvCtx->transferSyntaxList);
        free(prvCtx);
        prvCtx = (PRV_PRESENTATIONCONTEXTITEM*)LST_Dequeue(l);
    }
    LST_Destroy(l);
}
