package space.iseki.peparser;

import java.util.Arrays;
import java.util.List;

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

    public List<SectionFlag> getSectionFlagList() {
        return Arrays.stream(SectionFlag.values()).filter(this::contains).toList();
    }
}
