package space.iseki.peparser;

public enum DllCharacteristic {
    /**
     * Reserved, must be zero.
     */
    RESERVED_0001(0x0001),

    /**
     * Reserved, must be zero.
     */
    RESERVED_0002(0x0002),

    /**
     * Reserved, must be zero.
     */
    RESERVED_0004(0x0004),

    /**
     * Reserved, must be zero.
     */
    RESERVED_0008(0x0008),

    /**
     * Image can handle a high entropy 64-bit virtual address space.
     */
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA(0x0020),

    /**
     * DLL can be relocated at load time.
     */
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE(0x0040),

    /**
     * Code Integrity checks are enforced.
     */
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY(0x0080),

    /**
     * Image is NX compatible.
     */
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT(0x0100),

    /**
     * Isolation aware, but do not isolate the image.
     */
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION(0x0200),

    /**
     * Does not use structured exception (SE) handling. No SE handler may be called in this image.
     */
    IMAGE_DLLCHARACTERISTICS_NO_SEH(0x0400),

    /**
     * Do not bind the image.
     */
    IMAGE_DLLCHARACTERISTICS_NO_BIND(0x0800),

    /**
     * Image must execute in an AppContainer.
     */
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER(0x1000),

    /**
     * A WDM driver.
     */
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER(0x2000),

    /**
     * Image supports Control Flow Guard.
     */
    IMAGE_DLLCHARACTERISTICS_GUARD_CF(0x4000),

    /**
     * Terminal Server aware.
     */
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE(0x8000),
    ;
    public final short value;

    DllCharacteristic(int i) {
        this.value = (short) i;
    }
}

