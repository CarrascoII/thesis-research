static DH *get_dh1024(void)
{
    static unsigned char dhp_1024[] = {
        0xF7, 0x06, 0x62, 0xCF, 0xA8, 0x50, 0x7C, 0xEE, 0x5F, 0x4D,
        0xFA, 0x67, 0xE5, 0x36, 0x12, 0x8D, 0x52, 0x87, 0x96, 0x06,
        0xB7, 0xAF, 0x7C, 0xA1, 0x2D, 0xF8, 0x59, 0xEB, 0x60, 0x38,
        0x68, 0x5C, 0x2A, 0x79, 0x1E, 0x69, 0xD7, 0xF4, 0xC8, 0xB8,
        0x51, 0x77, 0x3A, 0x9F, 0x2D, 0x44, 0x0F, 0x9B, 0xE1, 0x43,
        0x44, 0x12, 0x2E, 0x24, 0x53, 0x87, 0x93, 0xB3, 0xDA, 0x81,
        0x62, 0x12, 0xDE, 0x5B, 0xFB, 0x20, 0x72, 0x12, 0x4D, 0xE3,
        0xE9, 0x82, 0x01, 0x6D, 0x1D, 0xA1, 0x3C, 0x50, 0xBD, 0xDF,
        0x3C, 0x43, 0x47, 0xE6, 0x3A, 0xFD, 0xF7, 0x8C, 0x58, 0xD2,
        0xA0, 0x3E, 0x1B, 0x41, 0xFF, 0xE5, 0x76, 0x88, 0x42, 0x17,
        0x1E, 0xD5, 0x0B, 0x2D, 0xEA, 0x60, 0x5B, 0xA7, 0xB0, 0x44,
        0x94, 0xF4, 0x13, 0x91, 0x45, 0x80, 0xD3, 0x98, 0xFF, 0x44,
        0x89, 0x4B, 0xDA, 0x64, 0xD0, 0x50, 0x3D, 0x8B
    };
    static unsigned char dhg_1024[] = {
        0x02
    };
    DH *dh = DH_new();
    BIGNUM *p, *g;

    if (dh == NULL)
        return NULL;
    p = BN_bin2bn(dhp_1024, sizeof(dhp_1024), NULL);
    g = BN_bin2bn(dhg_1024, sizeof(dhg_1024), NULL);
    if (p == NULL || g == NULL
            || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }
    return dh;
}
