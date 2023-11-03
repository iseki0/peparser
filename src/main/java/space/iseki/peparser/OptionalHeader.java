package space.iseki.peparser;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public record OptionalHeader(boolean pe32Plus,
                             int majorLinkerVersion,
                             int minorLinkerVersion,
                             int sizeOfCode,
                             int sizeOfInitializedData,
                             int sizeOfUninitializedData,
                             int addressOfEntryPoint,
                             int baseOfCode,
                             int baseOfData,
                             long imageBase,
                             int sectionAlignment,
                             int fileAlignment,
                             short majorOperatingSystemVersion,
                             short minorOperatingSystemVersion,
                             short majorImageVersion,
                             short minorImageVersion,
                             short majorSubsystemVersion,
                             short minorSubsystemVersion,
                             int win32VersionValue,
                             int sizeOfImage,
                             int sizeOfHeaders,
                             int checksum,
                             short subsystem,
                             short dllCharacteristics,
                             long sizeOfStackReserve,
                             long sizeOfStackCommit,
                             long sizeOfHeapReserve,
                             long sizeOfHeapCommit,
                             int loaderFlags,
                             int numberOfRvaAndSizes,
                             @NotNull ImageDataDirectory exportTable,
                             @NotNull ImageDataDirectory importTable,
                             @NotNull ImageDataDirectory resourceTable,
                             @NotNull ImageDataDirectory exceptionTable,
                             @NotNull ImageDataDirectory certificationTable,
                             @NotNull ImageDataDirectory baseRelocationTable,
                             @NotNull ImageDataDirectory debug,
                             @NotNull ImageDataDirectory globalPtr,
                             @NotNull ImageDataDirectory tlsTable,
                             @NotNull ImageDataDirectory loadConfigTable,
                             @NotNull ImageDataDirectory boundImport,
                             @NotNull ImageDataDirectory importAddressTable,
                             @NotNull ImageDataDirectory delayImportTable,
                             @NotNull ImageDataDirectory clrRuntimeHeader) {

    public boolean contains(DllCharacteristic dllCharacteristic) {
        return (this.dllCharacteristics & dllCharacteristic.value) != 0;
    }

    public @Nullable WindowsSubsystem getWindowsSubsystem() {
        return WindowsSubsystem.of(subsystem);
    }

}
