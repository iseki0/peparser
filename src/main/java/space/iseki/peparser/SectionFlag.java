package space.iseki.peparser;

public enum SectionFlag {
    /**
     * Reserved for future use.
     */
    RESERVED_00000000(0x00000000),

    /**
     * Reserved for future use.
     */
    RESERVED_00000001(0x00000001),

    /**
     * Reserved for future use.
     */
    RESERVED_00000002(0x00000002),

    /**
     * Reserved for future use.
     */
    RESERVED_00000004(0x00000004),

    /**
     * The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
     */
    IMAGE_SCN_TYPE_NO_PAD(0x00000008),

    /**
     * Reserved for future use.
     */
    RESERVED_00000010(0x00000010),

    /**
     * The section contains executable code.
     */
    IMAGE_SCN_CNT_CODE(0x00000020),

    /**
     * The section contains initialized data.
     */
    IMAGE_SCN_CNT_INITIALIZED_DATA(0x00000040),

    /**
     * The section contains uninitialized data.
     */
    IMAGE_SCN_CNT_UNINITIALIZED_DATA(0x00000080),

    /**
     * Reserved for future use.
     */
    IMAGE_SCN_LNK_OTHER(0x00000100),

    /**
     * The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
     */
    IMAGE_SCN_LNK_INFO(0x00000200),

    /**
     * Reserved for future use.
     */
    RESERVED_00000400(0x00000400),

    /**
     * The section will not become part of the image. This is valid only for object files.
     */
    IMAGE_SCN_LNK_REMOVE(0x00000800),

    /**
     * The section contains COMDAT data. For more information, see COMDAT Sections (Object Only). This is valid only for object files.
     */
    IMAGE_SCN_LNK_COMDAT(0x00001000),

    /**
     * The section contains data referenced through the global pointer (GP).
     */
    IMAGE_SCN_GPREL(0x00008000),

    /**
     * Reserved for future use.
     */
    IMAGE_SCN_MEM_PURGEABLE(0x00020000),

    /**
     * Reserved for future use.
     */
    IMAGE_SCN_MEM_16BIT(0x00020000),

    /**
     * Reserved for future use.
     */
    IMAGE_SCN_MEM_LOCKED(0x00040000),

    /**
     * Reserved for future use.
     */
    IMAGE_SCN_MEM_PRELOAD(0x00080000),

    /**
     * Align data on a 1-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_1BYTES(0x00100000),

    /**
     * Align data on a 2-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_2BYTES(0x00200000),

    /**
     * Align data on a 4-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_4BYTES(0x00300000),

    /**
     * Align data on an 8-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_8BYTES(0x00400000),

    /**
     * Align data on a 16-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_16BYTES(0x00500000),

    /**
     * Align data on a 32-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_32BYTES(0x00600000),

    /**
     * Align data on a 64-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_64BYTES(0x00700000),

    /**
     * Align data on a 128-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_128BYTES(0x00800000),

    /**
     * Align data on a 256-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_256BYTES(0x00900000),

    /**
     * Align data on a 512-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_512BYTES(0x00A00000),

    /**
     * Align data on a 1024-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_1024BYTES(0x00B00000),

    /**
     * Align data on a 2048-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_2048BYTES(0x00C00000),

    /**
     * Align data on a 4096-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_4096BYTES(0x00D00000),

    /**
     * Align data on an 8192-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_8192BYTES(0x00E00000),

    /**
     * The section contains extended relocations.
     */
    IMAGE_SCN_LNK_NRELOC_OVFL(0x01000000),

    /**
     * The section can be discarded as needed.
     */
    IMAGE_SCN_MEM_DISCARDABLE(0x02000000),

    /**
     * The section cannot be cached.
     */
    IMAGE_SCN_MEM_NOT_CACHED(0x04000000),

    /**
     * The section is not pageable.
     */
    IMAGE_SCN_MEM_NOT_PAGED(0x08000000),

    /**
     * The section can be shared in memory.
     */
    IMAGE_SCN_MEM_SHARED(0x10000000),

    /**
     * The section can be executed as code.
     */
    IMAGE_SCN_MEM_EXECUTE(0x20000000),

    /**
     * The section can be read.
     */
    IMAGE_SCN_MEM_READ(0x40000000),

    /**
     * The section can be written to.
     */
    IMAGE_SCN_MEM_WRITE(0x80000000),
    ;
    public final int value;

    SectionFlag(int i) {
        this.value = i;
    }
}
