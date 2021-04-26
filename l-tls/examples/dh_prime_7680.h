static DH *get_dh7680(void)
{
    static unsigned char dhp_7680[] = {
        0xA9, 0x9F, 0x54, 0x27, 0x6A, 0xB8, 0x15, 0xD6, 0x71, 0x5B,
        0xC5, 0x8C, 0xCF, 0x0D, 0x4C, 0xAF, 0x39, 0x81, 0x11, 0xAD,
        0x78, 0xCA, 0x2A, 0x93, 0x28, 0x06, 0x5B, 0x00, 0x99, 0x52,
        0x92, 0xEF, 0x75, 0x88, 0x96, 0x4C, 0xF2, 0xA0, 0xD7, 0x49,
        0xD7, 0x99, 0x7A, 0xFF, 0xA4, 0xAD, 0x31, 0x81, 0x3C, 0x23,
        0xB8, 0xB2, 0x60, 0xA3, 0xA0, 0xF8, 0x13, 0xB6, 0xAE, 0x5C,
        0x57, 0x7D, 0xA6, 0xF9, 0x21, 0xEF, 0x7D, 0x01, 0x05, 0x92,
        0x48, 0x92, 0xDA, 0xFE, 0x8F, 0x2F, 0xAE, 0x30, 0x67, 0x5B,
        0x5E, 0xE5, 0x22, 0x74, 0x0F, 0x9E, 0xA7, 0xE3, 0x4C, 0x2A,
        0x12, 0x2E, 0x3C, 0x63, 0xA4, 0x4F, 0x3B, 0xE1, 0xCE, 0x62,
        0x7B, 0xD6, 0x30, 0x3C, 0xBF, 0x23, 0x86, 0x60, 0x65, 0x57,
        0x9C, 0x7D, 0x7E, 0xD8, 0x38, 0x0B, 0x09, 0x42, 0xE4, 0xE8,
        0x24, 0x93, 0xE8, 0x72, 0xA9, 0x3E, 0x62, 0xF6, 0x5C, 0x86,
        0x64, 0xEF, 0x70, 0x3A, 0xAB, 0x7F, 0xF5, 0x8D, 0xE4, 0x06,
        0xE9, 0xBD, 0x86, 0x06, 0x79, 0xCD, 0xE5, 0xE4, 0x07, 0xCD,
        0x71, 0xDE, 0xBA, 0x37, 0x75, 0xD0, 0xEE, 0x85, 0x5D, 0x3A,
        0x6B, 0xAC, 0x0B, 0x1F, 0x23, 0x6B, 0x39, 0x9C, 0x2F, 0x49,
        0x67, 0xA7, 0xF4, 0x73, 0x5A, 0x22, 0xD9, 0x53, 0x5A, 0x1C,
        0x46, 0xDF, 0x1F, 0x32, 0xEB, 0x56, 0x8F, 0xA3, 0x85, 0x4F,
        0x9F, 0xE3, 0x1F, 0x77, 0x47, 0xB1, 0x00, 0xBB, 0x9F, 0xFE,
        0x19, 0x7B, 0x0D, 0x27, 0x35, 0xB6, 0x77, 0x63, 0x9D, 0xF8,
        0x29, 0x15, 0x33, 0xDD, 0x8D, 0xD1, 0x84, 0x1B, 0x35, 0x39,
        0xF8, 0xE6, 0xB9, 0x55, 0x66, 0x8B, 0xEF, 0xC4, 0xAD, 0xEB,
        0x14, 0xE9, 0x85, 0x90, 0x5F, 0xE5, 0xC2, 0xAD, 0xFB, 0xC2,
        0x6C, 0xF0, 0x91, 0x16, 0x7A, 0x27, 0xD2, 0xCD, 0x78, 0x50,
        0x99, 0x03, 0x34, 0x02, 0xEC, 0x14, 0xFC, 0x60, 0x32, 0xAC,
        0x76, 0xCC, 0xDE, 0x6D, 0xEB, 0x56, 0xAA, 0xDC, 0x8B, 0xC1,
        0x05, 0x8D, 0x92, 0xD3, 0x69, 0xCC, 0x76, 0x0A, 0xB2, 0x3F,
        0xFF, 0xF0, 0x61, 0x0E, 0xDD, 0x16, 0x7A, 0x98, 0xED, 0xAC,
        0x72, 0xC3, 0xAA, 0x5B, 0x9D, 0xCC, 0xE0, 0xB0, 0xB7, 0x01,
        0x3C, 0x6E, 0xAD, 0xBE, 0xC5, 0x48, 0x9D, 0xA6, 0x8B, 0xCA,
        0x11, 0x44, 0x65, 0x3D, 0x5D, 0x9A, 0xB8, 0x68, 0xF5, 0x27,
        0xD5, 0x92, 0xCD, 0x64, 0x16, 0x29, 0x96, 0xC3, 0x89, 0x5F,
        0xBD, 0x01, 0x0B, 0x33, 0x18, 0x7A, 0x65, 0x7C, 0xCB, 0x94,
        0x5F, 0xC4, 0xD9, 0x40, 0x5B, 0x37, 0xDE, 0x84, 0xD4, 0xBC,
        0xE8, 0x57, 0x3E, 0x2A, 0xC2, 0xAB, 0x35, 0x9D, 0x39, 0xDC,
        0xCB, 0x20, 0xB7, 0x72, 0x2F, 0xDF, 0x82, 0xBC, 0x28, 0xF0,
        0x68, 0x94, 0x55, 0x58, 0xF0, 0xCE, 0xA4, 0x82, 0xAA, 0xD1,
        0x23, 0x10, 0x6B, 0x5D, 0x73, 0x0B, 0x90, 0x81, 0x8A, 0xC5,
        0x6D, 0x79, 0x1C, 0x98, 0xB7, 0x2D, 0x7B, 0x54, 0x88, 0xD8,
        0x8C, 0x02, 0x45, 0x3E, 0xEF, 0xCA, 0x66, 0xF9, 0xCF, 0x49,
        0x80, 0x0E, 0x49, 0xB9, 0xA6, 0xC1, 0xB3, 0x32, 0x05, 0x35,
        0x68, 0x6A, 0x01, 0xB5, 0x61, 0x94, 0x2C, 0xDC, 0xFC, 0x53,
        0x62, 0x2D, 0x9D, 0xF5, 0xA1, 0x0F, 0xA7, 0x6D, 0x0C, 0x29,
        0x10, 0x60, 0x3C, 0x9A, 0x09, 0x4F, 0x01, 0xED, 0xF5, 0x39,
        0xB7, 0xB2, 0x8C, 0x75, 0xAB, 0x5A, 0x6E, 0xB0, 0x10, 0x1E,
        0x42, 0x59, 0x04, 0xBA, 0x44, 0x0C, 0x96, 0x98, 0xE6, 0xC6,
        0xD1, 0x9F, 0xEC, 0xFE, 0x70, 0x3B, 0xFA, 0x0C, 0x0D, 0x65,
        0x62, 0xDE, 0x1A, 0xDA, 0x58, 0x4A, 0xE7, 0xBC, 0xD5, 0x79,
        0x5A, 0x19, 0x9C, 0x5A, 0xBB, 0xBE, 0x7C, 0x3E, 0xBB, 0xDB,
        0x75, 0x7A, 0xA3, 0x1B, 0x32, 0xD0, 0x8C, 0x5D, 0xEF, 0x02,
        0x86, 0xCA, 0x25, 0x76, 0x5F, 0x8A, 0xCC, 0x3C, 0xAF, 0x82,
        0xD3, 0xE2, 0x83, 0x4C, 0xD5, 0xD6, 0xBB, 0xC0, 0xAB, 0xA8,
        0x2F, 0xB8, 0x12, 0x0C, 0x7E, 0x19, 0x40, 0xDE, 0xED, 0x59,
        0xC2, 0xAB, 0x3C, 0x2D, 0x47, 0xF4, 0x99, 0x39, 0xFA, 0x6F,
        0x3D, 0x7E, 0xB7, 0xCA, 0xF6, 0x17, 0x8A, 0x74, 0xED, 0x37,
        0x3E, 0xE1, 0x69, 0x6D, 0xD3, 0x32, 0x05, 0x79, 0xD0, 0x6E,
        0x93, 0x69, 0xF7, 0xC3, 0xB6, 0x7E, 0xB3, 0x11, 0x8D, 0x37,
        0x5D, 0x35, 0xC3, 0xFD, 0xBF, 0xEA, 0x7C, 0xA7, 0xA5, 0x1D,
        0x0A, 0x74, 0xA8, 0x1E, 0x93, 0x7C, 0x9C, 0xE6, 0x63, 0x72,
        0x5D, 0x97, 0xBC, 0x10, 0x30, 0xCD, 0x40, 0x53, 0x7B, 0xE9,
        0xB6, 0xB5, 0x5A, 0xDC, 0x1A, 0x8A, 0xB6, 0xCF, 0x73, 0x1B,
        0x1E, 0x54, 0x4B, 0xC6, 0xDB, 0x87, 0x05, 0xDE, 0xBF, 0xC4,
        0xCC, 0xE0, 0x93, 0x91, 0x27, 0x1C, 0xF2, 0xDE, 0x3E, 0xEF,
        0x64, 0x6F, 0xC3, 0x5B, 0x81, 0x90, 0x00, 0x57, 0xE5, 0x1B,
        0x47, 0x2B, 0x78, 0x04, 0x99, 0x46, 0x78, 0x17, 0x93, 0x49,
        0x26, 0x33, 0x77, 0x83, 0x9A, 0x9B, 0xCB, 0x86, 0xC3, 0x2C,
        0x11, 0x99, 0xF9, 0x1A, 0xAB, 0x28, 0xFE, 0x18, 0xD2, 0xB3,
        0xD8, 0x96, 0x45, 0x5A, 0x48, 0x56, 0x0B, 0x6F, 0x66, 0xAE,
        0x7B, 0x64, 0x85, 0x46, 0x31, 0xCC, 0x2E, 0xC8, 0xA3, 0x0C,
        0x47, 0x0C, 0xBC, 0xE2, 0xA9, 0xA5, 0x54, 0x84, 0x82, 0x9D,
        0x1A, 0x31, 0x93, 0x8F, 0x77, 0x90, 0xAB, 0x09, 0x1C, 0x71,
        0x03, 0x44, 0x07, 0x3C, 0x97, 0x03, 0x19, 0xA6, 0xA0, 0x99,
        0xCD, 0xC7, 0x71, 0x86, 0x1C, 0x00, 0x07, 0xB7, 0xBC, 0x65,
        0xF9, 0x13, 0x83, 0x0E, 0xD1, 0xCA, 0x1D, 0xA6, 0xAA, 0xD3,
        0xE8, 0x11, 0x84, 0x28, 0xC3, 0xEB, 0x00, 0x22, 0xFB, 0x91,
        0xDE, 0xFF, 0x62, 0x0A, 0xD0, 0xBE, 0x16, 0x44, 0x58, 0x20,
        0x2D, 0x62, 0x16, 0xC6, 0x82, 0x1C, 0x11, 0x12, 0x8D, 0x5A,
        0xBA, 0xE4, 0x94, 0x6A, 0xE8, 0x3E, 0x64, 0x4B, 0x11, 0xA5,
        0x28, 0x76, 0x65, 0x13, 0xF9, 0xCA, 0x71, 0x57, 0x25, 0x2B,
        0x2D, 0x87, 0xFB, 0x13, 0xE7, 0x1B, 0x8C, 0x3D, 0x11, 0x99,
        0xAB, 0x09, 0xE5, 0xCF, 0x11, 0x7A, 0xD1, 0x26, 0xF9, 0x77,
        0x95, 0x33, 0x83, 0x6B, 0x63, 0x7E, 0x9D, 0xD4, 0xD5, 0xBA,
        0xBD, 0xE3, 0x3B, 0xE8, 0x37, 0x2B, 0x1F, 0x44, 0x78, 0x53,
        0x4E, 0x1F, 0xF5, 0x36, 0x93, 0x8F, 0x2D, 0x44, 0x49, 0xEC,
        0xFD, 0x66, 0x3C, 0xC2, 0xD4, 0xF8, 0x14, 0x14, 0x5D, 0xC1,
        0x99, 0x04, 0x19, 0x59, 0x20, 0xFD, 0xA6, 0xC7, 0x19, 0xC0,
        0x38, 0xC9, 0x48, 0x0C, 0xFE, 0x9F, 0x03, 0x90, 0x4D, 0xF8,
        0x24, 0x2B, 0xF4, 0xC5, 0x0A, 0x23, 0xC3, 0x42, 0x6F, 0x1C,
        0xFD, 0x1C, 0xAC, 0x40, 0xB3, 0x9E, 0xEC, 0x3F, 0x9C, 0x9F,
        0x3A, 0xF0, 0xA8, 0xAF, 0x5E, 0x66, 0x8C, 0x0E, 0xD3, 0xD3,
        0xBD, 0xB0, 0xB1, 0xEF, 0xE0, 0xE8, 0xCE, 0xA6, 0xB7, 0x96,
        0x88, 0x44, 0xAE, 0x62, 0x76, 0xAE, 0x9C, 0x8B, 0x43, 0xC0,
        0x71, 0x67, 0x1C, 0x72, 0x0F, 0x34, 0x70, 0x63, 0x03, 0x7A,
        0x08, 0x3E, 0x6B, 0xE1, 0xC8, 0xB6, 0x60, 0xA1, 0x48, 0xCA,
        0x2B, 0x31, 0x7A, 0x5B, 0xD8, 0x23, 0xC3, 0x80, 0x2E, 0x1B
    };
    static unsigned char dhg_7680[] = {
        0x02
    };
    DH *dh = DH_new();
    BIGNUM *p, *g;

    if (dh == NULL)
        return NULL;
    p = BN_bin2bn(dhp_7680, sizeof(dhp_7680), NULL);
    g = BN_bin2bn(dhg_7680, sizeof(dhg_7680), NULL);
    if (p == NULL || g == NULL
            || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }
    return dh;
}
