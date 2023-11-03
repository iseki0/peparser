package space.iseki.peparser;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.time.Instant;
import java.util.Optional;

public record CoffHeader(short machine,
                         int numbersOfSections,
                         int timeDateStamp,
                         int sizeOfOptionalHeader,
                         short characteristics) {
    public static final int LENGTH = 20;

    public @NotNull Instant getTimeDateStampInstant() {
        return Instant.ofEpochSecond(timeDateStamp & PEFile.INT_MASK);
    }

    public @Nullable MachineType getMachineType() {
        return MachineType.of(machine);
    }

    public @NotNull MachineType getMachineTypeOrDefault() {
        return Optional.ofNullable(MachineType.of(machine)).orElse(MachineType.IMAGE_FILE_MACHINE_UNKNOWN);
    }

    public boolean contains(Characteristic characteristic) {
        return (characteristic.value & characteristics) != 0;
    }

}

