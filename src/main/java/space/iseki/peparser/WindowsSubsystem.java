package space.iseki.peparser;

import org.jetbrains.annotations.Nullable;

import java.util.Arrays;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum WindowsSubsystem {
    /**
     * An unknown subsystem
     */
    IMAGE_SUBSYSTEM_UNKNOWN(0),

    /**
     * Device drivers and native Windows processes
     */
    IMAGE_SUBSYSTEM_NATIVE(1),

    /**
     * The Windows graphical user interface (GUI) subsystem
     */
    IMAGE_SUBSYSTEM_WINDOWS_GUI(2),

    /**
     * The Windows character subsystem
     */
    IMAGE_SUBSYSTEM_WINDOWS_CUI(3),

    /**
     * The OS/2 character subsystem
     */
    IMAGE_SUBSYSTEM_OS2_CUI(5),

    /**
     * The Posix character subsystem
     */
    IMAGE_SUBSYSTEM_POSIX_CUI(7),

    /**
     * Native Win9x driver
     */
    IMAGE_SUBSYSTEM_NATIVE_WINDOWS(8),

    /**
     * Windows CE
     */
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI(9),

    /**
     * An Extensible Firmware Interface (EFI) application
     */
    IMAGE_SUBSYSTEM_EFI_APPLICATION(10),

    /**
     * An EFI driver with boot services
     */
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER(11),

    /**
     * An EFI driver with run-time services
     */
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER(12),

    /**
     * An EFI ROM image
     */
    IMAGE_SUBSYSTEM_EFI_ROM(13),

    /**
     * XBOX
     */
    IMAGE_SUBSYSTEM_XBOX(14),

    /**
     * Windows boot application.
     */
    IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION(16),
    ;
    private static final Map<Short, WindowsSubsystem> m = Arrays.stream(WindowsSubsystem.values())
            .collect(Collectors.toMap(i -> i.value, Function.identity()));
    public final short value;

    WindowsSubsystem(int i) {
        this.value = (short) i;
    }

    public static @Nullable WindowsSubsystem of(short i) {
        return m.get(i);
    }
}
