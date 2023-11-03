package space.iseki.peparser;

public record SectionHeader(String name,
                            int virtualSize,
                            int virtualAddress,
                            int sizeOfRawData,
                            int pointerToRawData,
                            int pointerToRelocations,
                            int pointerToLineNumbers,
                            int numberOfRelocations,
                            int numberOfLineNumbers,
                            int characteristics) {
    public static final int LENGTH = 40;

    public boolean contains(SectionFlag sectionFlag) {
        return (sectionFlag.value & this.characteristics) != 0;
    }
}
