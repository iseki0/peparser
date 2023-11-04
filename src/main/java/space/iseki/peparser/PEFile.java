package space.iseki.peparser;

import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;


public class PEFile implements AutoCloseable {
    public static final int PE_SIGNATURE_OFFSET = 0x3c;
    public static final short PE32 = 0x010b;
    public static final short PE32PLUS = 0x020b;
    static final long INT_MASK = 0xffffffffL;
    static final int SHORT_MASK = 0xffff;
    private static final VarHandle INT_LE_AH = MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.LITTLE_ENDIAN);
    private static final VarHandle SHORT_LE_AH = MethodHandles.byteArrayViewVarHandle(short[].class, ByteOrder.LITTLE_ENDIAN);
    private static final VarHandle LONG_LE_AH = MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.LITTLE_ENDIAN);
    private static final byte[] PE_SIGNATURE = new byte[]{'P', 'E', 0, 0};
    private final CoffHeader coffHeader;
    private final OptionalHeader optionalHeader;
    private final List<SectionHeader> sections;
    private final RandomAccessFile raf;
    private final List<ResourceTreeNode> resourceTreeNodes;

    private PEFile(CoffHeader coffHeader, OptionalHeader optionalHeader, RandomAccessFile raf, List<SectionHeader> sections) throws IOException {
        this.coffHeader = coffHeader;
        this.optionalHeader = optionalHeader;
        this.raf = raf;
        this.sections = sections;
        var rsrc = sections.stream().filter(i -> i.name().equals(".rsrc")).findFirst().orElse(null);
        this.resourceTreeNodes = rsrc == null ? Collections.emptyList() : List.of(readRsrcNode(rsrc.pointerToRawData(), rsrc.pointerToRawData(), 0));
    }

    /**
     * Open a PE file.
     *
     * @param file the PE file
     */
    public static @NotNull PEFile open(@NotNull File file) throws IOException {
        var raf = new RandomAccessFile(file, "r");
        try {
            raf.seek(PE_SIGNATURE_OFFSET);
            var b4 = new byte[4];
            raf.readFully(b4);
            var positionToSignature = (int) INT_LE_AH.get(b4, 0) & INT_MASK;
            raf.seek(positionToSignature);
            var coffHeaderData = new byte[CoffHeader.LENGTH + 4];
            raf.readFully(coffHeaderData);
            if (!checkPESignature(coffHeaderData)) throw new IllegalArgumentException("PE signature not match");
            CoffHeader coffHeader = readCoffHeader(coffHeaderData, 4);
            var optionalHeaderData = new byte[coffHeader.sizeOfOptionalHeader()];
            raf.readFully(optionalHeaderData);
            OptionalHeader optionalHeader = readOptionalHeader(optionalHeaderData, 0);
            var sections = new SectionHeader[coffHeader.numbersOfSections()];
            var sectionData = new byte[SectionHeader.LENGTH * sections.length];
            raf.readFully(sectionData);
            for (int i = 0; i < coffHeader.numbersOfSections(); i++) {
                sections[i] = readSectionHeader(sectionData, i * SectionHeader.LENGTH);
            }
            var pe = new PEFile(coffHeader, optionalHeader, raf, List.of(sections));
            return pe;
        } catch (Throwable th) {
            try {
                raf.close();
            } catch (IOException e) {
                th.addSuppressed(e);
            }
            throw th;
        }
    }

    private static boolean checkPESignature(byte[] data) {
        return Arrays.equals(PE_SIGNATURE, 0, 4, data, 0, 4);
    }

    private static CoffHeader readCoffHeader(byte[] bytes, int off) {
        var m = (short) SHORT_LE_AH.get(bytes, 0);
        var n = (short) SHORT_LE_AH.get(bytes, 2 + off) & 0xffff;
        var t = (int) INT_LE_AH.get(bytes, 4 + off);
        var s = (short) SHORT_LE_AH.get(bytes, 16 + off) & 0xffff;
        var c = (short) SHORT_LE_AH.get(bytes, 18 + off);
        return new CoffHeader(m, n, t, s, c);
    }

    private static OptionalHeader readOptionalHeader(byte[] bytes, int off) {
        var reader = new IntReader(bytes, off);
        short magic = reader.readShort();
        boolean pe32Plus = magic == PE32PLUS;
        if (!pe32Plus && magic != PE32) throw new IllegalArgumentException("optional header magic not match");
        int majorLinkerVersion = reader.readByte();
        int minorLinkerVersion = reader.readByte();
        int sizeOfCode = reader.readInt();
        int sizeOfInitializedData = reader.readInt();
        int sizeOfUninitializedData = reader.readInt();
        int addressOfEntryPoint = reader.readInt();
        int baseOfCode = reader.readInt();
        int baseOfData = pe32Plus ? 0 : reader.readInt();
        long imageBase = pe32Plus ? reader.readLong() : reader.readInt() & INT_MASK;
        int sectionAlignment = reader.readInt();
        int fileAlignment = reader.readInt();
        short majorOperatingSystemVersion = reader.readShort();
        short minorOperatingSystemVersion = reader.readShort();
        short majorImageVersion = reader.readShort();
        short minorImageVersion = reader.readShort();
        short majorSubsystemVersion = reader.readShort();
        short minorSubsystemVersion = reader.readShort();
        int win32VersionValue = reader.readInt();
        int sizeOfImage = reader.readInt();
        int sizeOfHeaders = reader.readInt();
        int checksum = reader.readInt();
        short subsystem = reader.readShort();
        short dllCharacteristics = reader.readShort();
        long sizeOfStackReserve = pe32Plus ? reader.readLong() : reader.readInt() & INT_MASK;
        long sizeOfStackCommit = pe32Plus ? reader.readLong() : reader.readInt() & INT_MASK;
        long sizeOfHeapReserve = pe32Plus ? reader.readLong() : reader.readInt() & INT_MASK;
        long sizeOfHeapCommit = pe32Plus ? reader.readLong() : reader.readInt() & INT_MASK;
        int loaderFlags = reader.readInt();
        int numberOfRvaAndSizes = reader.readInt();
        ImageDataDirectory exportTable = readImageDataDirectory(reader, numberOfRvaAndSizes, 0);
        ImageDataDirectory importTable = readImageDataDirectory(reader, numberOfRvaAndSizes, 1);
        ImageDataDirectory resourceTable = readImageDataDirectory(reader, numberOfRvaAndSizes, 2);
        ImageDataDirectory exceptionTable = readImageDataDirectory(reader, numberOfRvaAndSizes, 3);
        ImageDataDirectory certificationTable = readImageDataDirectory(reader, numberOfRvaAndSizes, 4);
        ImageDataDirectory baseRelocationTable = readImageDataDirectory(reader, numberOfRvaAndSizes, 5);
        ImageDataDirectory debug = readImageDataDirectory(reader, numberOfRvaAndSizes, 6);
        readImageDataDirectory(reader, numberOfRvaAndSizes, 7);
        ImageDataDirectory globalPtr = readImageDataDirectory(reader, numberOfRvaAndSizes, 8);
        ImageDataDirectory tlsTable = readImageDataDirectory(reader, numberOfRvaAndSizes, 9);
        ImageDataDirectory loadConfigTable = readImageDataDirectory(reader, numberOfRvaAndSizes, 10);
        ImageDataDirectory boundImport = readImageDataDirectory(reader, numberOfRvaAndSizes, 11);
        ImageDataDirectory importAddressTable = readImageDataDirectory(reader, numberOfRvaAndSizes, 12);
        ImageDataDirectory delayImportTable = readImageDataDirectory(reader, numberOfRvaAndSizes, 13);
        ImageDataDirectory clrRuntimeHeader = readImageDataDirectory(reader, numberOfRvaAndSizes, 14);
        readImageDataDirectory(reader, numberOfRvaAndSizes, 15);
        return new OptionalHeader(pe32Plus, majorLinkerVersion, minorLinkerVersion, sizeOfCode, sizeOfInitializedData, sizeOfUninitializedData, addressOfEntryPoint, baseOfCode, baseOfData, imageBase, sectionAlignment, fileAlignment, majorOperatingSystemVersion, minorOperatingSystemVersion, majorImageVersion, minorImageVersion, majorSubsystemVersion, minorSubsystemVersion, win32VersionValue, sizeOfImage, sizeOfHeaders, checksum, subsystem, dllCharacteristics, sizeOfStackReserve, sizeOfStackCommit, sizeOfHeapReserve, sizeOfHeapCommit, loaderFlags, numberOfRvaAndSizes, exportTable, importTable, resourceTable, exceptionTable, certificationTable, baseRelocationTable, debug, globalPtr, tlsTable, loadConfigTable, boundImport, importAddressTable, delayImportTable, clrRuntimeHeader);
    }

    private static ImageDataDirectory readImageDataDirectory(IntReader reader, int noras, int n) {
        if (n >= noras) return ImageDataDirectory.ZERO;
        return new ImageDataDirectory(reader.readInt(), reader.readInt());
    }

    private static SectionHeader readSectionHeader(byte[] data, int off) {
        var nameLen = 0;
        for (; nameLen < 8; nameLen++) {
            if (data[nameLen + off] == 0) break;
        }
        String name = new String(data, off, nameLen, StandardCharsets.UTF_8);
        int virtualSize = (int) INT_LE_AH.get(data, off + 8);
        int virtualAddress = (int) INT_LE_AH.get(data, off + 12);
        int sizeOfRawData = (int) INT_LE_AH.get(data, off + 16);
        int pointerToRawData = (int) INT_LE_AH.get(data, off + 20);
        int pointerToRelocations = (int) INT_LE_AH.get(data, off + 24);
        int pointerToLineNumbers = (int) INT_LE_AH.get(data, off + 28);
        int numberOfRelocations = (short) SHORT_LE_AH.get(data, off + 32) & SHORT_MASK;
        int numberOfLineNumbers = (short) SHORT_LE_AH.get(data, off + 34) & SHORT_MASK;
        int characteristics = (int) INT_LE_AH.get(data, off + 36);
        return new SectionHeader(name, virtualSize, virtualAddress, sizeOfRawData, pointerToRawData, pointerToRelocations, pointerToLineNumbers, numberOfRelocations, numberOfLineNumbers, characteristics);
    }

    private static ResourceDirectoryTable readResourceDirectoryTable(byte[] bytes, int off) {
        int characteristic = (int) INT_LE_AH.get(bytes, off);
        int timeDateStamp = (int) INT_LE_AH.get(bytes, off + 4);
        short majorVersion = (short) SHORT_LE_AH.get(bytes, off + 8);
        short minorVersion = (short) SHORT_LE_AH.get(bytes, off + 10);
        short numberOfNameEntries = (short) SHORT_LE_AH.get(bytes, off + 12);
        short numberOfIdEntries = (short) SHORT_LE_AH.get(bytes, off + 14);
        return new ResourceDirectoryTable(characteristic, timeDateStamp, majorVersion, minorVersion, numberOfNameEntries, numberOfIdEntries);
    }

    private static ResourceData readResourceData(byte[] bytes, int off) {
        return new ResourceData((Integer) INT_LE_AH.get(bytes, off), (Integer) INT_LE_AH.get(bytes, off + 4), (Integer) INT_LE_AH.get(bytes, off + 8));
    }

    private ResourceTreeNode[] readRsrcNode(long base, long posToTable, int depth) throws IOException {
        if (depth > 2) {
            throw new IllegalStateException("too deep, Windows only use three level resources");
        }
        assert depth >= 0;
        assert base >= 0;
        assert posToTable >= base;
        raf.seek(posToTable);
        var b16 = new byte[16];
        raf.readFully(b16);
        var table = readResourceDirectoryTable(b16, 0);
        int numberOfNameEntries = table.numberOfNameEntries() & SHORT_MASK;
        int numberOfIdEntries = table.numberOfIdEntries() & SHORT_MASK;
        int totalEntries = numberOfNameEntries + numberOfIdEntries;
        var entryDataBuffer = new byte[8 * totalEntries];
        raf.readFully(entryDataBuffer);
        // read name
        var nameList = new String[numberOfNameEntries];
        for (int i = 0; i < nameList.length; i++) {
            // i * 8, the first field
            var nameOffset = (int) INT_LE_AH.get(entryDataBuffer, i * 8) & INT_MASK;
            // clear high bit
            nameOffset = nameOffset & Integer.MAX_VALUE;
            // calculate address
            nameOffset += base;
            raf.seek(nameOffset);
            // read string length, but in BE
            var len = raf.readUnsignedShort();
            // convert to LE
            len = (len & 0xff00) >> 8 | (len & 0xff) << 8;
            len = len * 2;
            // prepare buffer and read string content
            var nameBuffer = new byte[len];
            raf.readFully(nameBuffer);
            nameList[i] = new String(nameBuffer, StandardCharsets.UTF_16LE);
        }
        var treeNodes = new ResourceTreeNode[totalEntries];
        var rdBuf = new byte[12];
        for (int i = 0; i < totalEntries; i++) {
            // i * 8 + 4, the second field, if the highest bit is 1, the integer will be negative .
            long offset = (int) INT_LE_AH.get(entryDataBuffer, i * 8 + 4);
            // high bit 0, leaf
            var isLeaf = offset >= 0;
            // clear high bit 1
            offset = offset & Integer.MAX_VALUE;
            var isNameNode = i < numberOfNameEntries;
            // named node without id
            var id = isNameNode ? 0 : (int) INT_LE_AH.get(entryDataBuffer, i * 8);
            // otherwise use name
            var name = isNameNode ? nameList[i] : null;
            if (isLeaf) {
                var rdOffset = base + offset;
                raf.seek(rdOffset);
                raf.readFully(rdBuf);
                var rd = readResourceData(rdBuf, 0);
                treeNodes[i] = new ResourceTreeNode(Collections.emptyList(), name, id, rd);
                continue;
            }
            // not leaf, recursive
            var children = List.of(readRsrcNode(base, offset + base, depth + 1));
            treeNodes[i] = new ResourceTreeNode(children, name, id, null);
        }
        return treeNodes;
    }

    /**
     * Get parsed COFF header.
     */
    public @NotNull CoffHeader getCoffHeader() {
        return coffHeader;
    }

    /**
     * Get parsed Optional header.
     */
    public @NotNull OptionalHeader getOptionalHeader() {
        return optionalHeader;
    }

    /**
     * Get parsed section headers.
     *
     * @return the list is unmodifiable
     */
    public @NotNull List<@NotNull SectionHeader> getSections() {
        return sections;
    }

    public @NotNull List<ResourceTreeNode> getResourceTree() {
        return resourceTreeNodes;
    }

    @Override
    public void close() throws Exception {
        this.raf.close();
    }

}

