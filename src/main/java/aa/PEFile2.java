package aa;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.ByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;

public class PEFile2 {
    public static final short MAGIC_PE_LE = 0x010b;
    public static final short MAGIC_PEPLUS_LE = 0x020b;
    private static final long PE_SIGNATURE_OFFSET_OFFSET = 0x3c;
    private static final long PE_SIGNATURE_LE = 0x00004550;
    private final SeekableByteChannel channel;
    private final List<SectionHeader> sectionHeaders;
    private boolean sectionHeaderReadFailed;

    public PEFile2(SeekableByteChannel channel) throws IOException {
        this.channel = channel;
        channel.position(PE_SIGNATURE_OFFSET_OFFSET);
        ByteBuffer peSignatureOffsetBuffer = ByteBuffer.allocate(4);
        readFully(channel, peSignatureOffsetBuffer);
        peSignatureOffsetBuffer.flip();
        peSignatureOffsetBuffer.order(ByteOrder.LITTLE_ENDIAN);
        long peSignatureOffset = peSignatureOffsetBuffer.getInt() & 0xffffffffL;

        channel.position(peSignatureOffset);
        ByteBuffer coffBuffer = ByteBuffer.allocate(24);
        readFully(channel, coffBuffer);
        coffBuffer.flip();
        coffBuffer.order(ByteOrder.LITTLE_ENDIAN);
        int peSignature = coffBuffer.getInt();
        if (peSignature != PE_SIGNATURE_LE) {
            throw new PEFileException("Invalid PE signature: " + HexFormat.of().toHexDigits(peSignature));
        }
        short machine = coffBuffer.getShort();
        int numberOfSections = coffBuffer.getShort() & 0xffff;
        long timeDateStamp = coffBuffer.getInt() & 0xffffffffL;
        long pointerToSymbolTable = coffBuffer.getInt() & 0xffffffffL;
        long numberOfSymbols = coffBuffer.getInt() & 0xffffffffL;
        int sizeOfOptionalHeader = coffBuffer.getShort() & 0xffff;
        short characteristics = coffBuffer.getShort();
        assert coffBuffer.remaining() == 0;

        ByteBuffer optionalHeaderBuffer = ByteBuffer.allocate(sizeOfOptionalHeader);
        readFully(channel, optionalHeaderBuffer);
        optionalHeaderBuffer.flip();
        optionalHeaderBuffer.order(ByteOrder.LITTLE_ENDIAN);
        short magic = optionalHeaderBuffer.getShort();
        if (magic != MAGIC_PE_LE && magic != MAGIC_PEPLUS_LE) {
            throw new PEFileException("Invalid magic: " + HexFormat.of().toHexDigits(magic));
        }
        boolean isPlus = magic == MAGIC_PEPLUS_LE;
        int majorLinkerVersion = optionalHeaderBuffer.get() & 0xff;
        int minorLinkerVersion = optionalHeaderBuffer.get() & 0xff;
        long sizeOfCode = getIntAsLong(optionalHeaderBuffer);
        long sizeOfInitializedData = getIntAsLong(optionalHeaderBuffer);
        long sizeOfUninitializedData = getIntAsLong(optionalHeaderBuffer);
        long addressOfEntryPoint = getIntAsLong(optionalHeaderBuffer);
        long baseOfCode = getIntAsLong(optionalHeaderBuffer);
        long baseOfData = isPlus ? 0 : getIntAsLong(optionalHeaderBuffer);
        long imageBase = isPlus ? optionalHeaderBuffer.getLong() : getIntAsLong(optionalHeaderBuffer);
        long sectionAlignment = getIntAsLong(optionalHeaderBuffer);
        long fileAlignment = getIntAsLong(optionalHeaderBuffer);
        int majorOperatingSystemVersion = getShortAsInt(optionalHeaderBuffer);
        int minorOperatingSystemVersion = getShortAsInt(optionalHeaderBuffer);
        int majorImageVersion = getShortAsInt(optionalHeaderBuffer);
        int minorImageVersion = getShortAsInt(optionalHeaderBuffer);
        int majorSubsystemVersion = getShortAsInt(optionalHeaderBuffer);
        int minorSubsystemVersion = getShortAsInt(optionalHeaderBuffer);
        long win32VersionValue = getIntAsLong(optionalHeaderBuffer);
        long sizeOfImage = getIntAsLong(optionalHeaderBuffer);
        long sizeOfHeaders = getIntAsLong(optionalHeaderBuffer);
        long checkSum = getIntAsLong(optionalHeaderBuffer);
        short subsystem = optionalHeaderBuffer.getShort();
        short dllCharacteristics = optionalHeaderBuffer.getShort();
        long sizeOfStackReserve = isPlus ? optionalHeaderBuffer.getLong() : getIntAsLong(optionalHeaderBuffer);
        long sizeOfStackCommit = isPlus ? optionalHeaderBuffer.getLong() : getIntAsLong(optionalHeaderBuffer);
        long sizeOfHeapReserve = isPlus ? optionalHeaderBuffer.getLong() : getIntAsLong(optionalHeaderBuffer);
        long sizeOfHeapCommit = isPlus ? optionalHeaderBuffer.getLong() : getIntAsLong(optionalHeaderBuffer);
        int loaderFlags = optionalHeaderBuffer.getInt();
        if (loaderFlags != 0) {
            throw new PEFileException("LoaderFlags must be 0");
        }
        int numberOfRvaAndSizes = optionalHeaderBuffer.getInt();
        long exportTableRva = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 1, numberOfRvaAndSizes);
        long exportTableSize = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 1, numberOfRvaAndSizes);
        long importTableRva = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 2, numberOfRvaAndSizes);
        long importTableSize = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 2, numberOfRvaAndSizes);
        long resourceTableRva = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 3, numberOfRvaAndSizes);
        long resourceTableSize = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 3, numberOfRvaAndSizes);
        long exceptionTableRva = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 4, numberOfRvaAndSizes);
        long exceptionTableSize = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 4, numberOfRvaAndSizes);
        long certificateTableRva = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 5, numberOfRvaAndSizes);
        long certificateTableSize = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 5, numberOfRvaAndSizes);
        long baseRelocationTableRva = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 6, numberOfRvaAndSizes);
        long baseRelocationTableSize = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 6, numberOfRvaAndSizes);
        long debugRva = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 7, numberOfRvaAndSizes);
        long debugSize = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 7, numberOfRvaAndSizes);
        long architectureRva = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 8, numberOfRvaAndSizes);
        long architectureSize = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 8, numberOfRvaAndSizes);
        long globalPtrRva = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 9, numberOfRvaAndSizes);
        long globalPtrSize = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 9, numberOfRvaAndSizes);
        long tlsTableRva = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 10, numberOfRvaAndSizes);
        long tlsTableSize = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 10, numberOfRvaAndSizes);
        long loadConfigTableRva = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 11, numberOfRvaAndSizes);
        long loadConfigTableSize = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 11, numberOfRvaAndSizes);
        long boundImportRva = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 12, numberOfRvaAndSizes);
        long boundImportSize = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 12, numberOfRvaAndSizes);
        long iatRva = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 13, numberOfRvaAndSizes);
        long iatSize = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 13, numberOfRvaAndSizes);
        long delayImportDescriptorRva = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 14, numberOfRvaAndSizes);
        long delayImportDescriptorSize = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 14, numberOfRvaAndSizes);
        long clrRuntimeHeaderRva = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 15, numberOfRvaAndSizes);
        long clrRuntimeHeaderSize = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 15, numberOfRvaAndSizes);
        long reservedRva = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 16, numberOfRvaAndSizes);
        long reservedSize = getOptionalHeaderDataDirectoryField(optionalHeaderBuffer, 16, numberOfRvaAndSizes);
        if (reservedRva != 0 || reservedSize != 0) {
            throw new PEFileException("ReservedRva and ReservedSize must be 0");
        }
        SectionHeader[] sectionHeaderArr = new SectionHeader[numberOfSections];
        try {
            ByteBuffer sectionHeadersBuffer = ByteBuffer.allocate(numberOfSections * 40);
            readFully(channel, sectionHeadersBuffer);
            sectionHeadersBuffer.flip();
            sectionHeadersBuffer.order(ByteOrder.LITTLE_ENDIAN);
            for (int i = 0; i < numberOfSections; i++) {
                sectionHeaderArr[i] = new SectionHeader(sectionHeadersBuffer);
            }
            assert sectionHeadersBuffer.remaining() == 0;
        } catch (EOFException ignored) {
            this.sectionHeaderReadFailed = true;
        }
        this.sectionHeaders = List.of(sectionHeaderArr);
    }

    private static void readFully(ByteChannel channel, ByteBuffer buffer) throws IOException {
        while (buffer.hasRemaining()) {
            if (channel.read(buffer) == -1) {
                throw new EOFException("Unexpected EOF");
            }
        }
    }

    private static long getIntAsLong(ByteBuffer buffer) {
        return buffer.getInt() & 0xffffffffL;
    }

    private static int getShortAsInt(ByteBuffer buffer) {
        return buffer.getShort() & 0xffff;
    }

    private static long getOptionalHeaderDataDirectoryField(ByteBuffer buffer, int index, int numberOfRvaAndSizes) {
        return numberOfRvaAndSizes >= index ? getIntAsLong(buffer) : 0;
    }

    public static void main(String[] args) throws IOException {
        try {
            PEFile2 peFile = new PEFile2(Files.newByteChannel(Path.of("C:\\Users\\iseki\\working\\peparser\\src\\test\\resources\\space\\iseki\\peparser\\ScreenOff.exe")));
            System.out.println("aaaaaaaaa");
        } catch (Throwable th) {
            th.printStackTrace();
        }
    }

    static class SectionHeader {
        private final String name;
        private final int virtualSize;
        private final int virtualAddress;
        private final int sizeOfRawData;
        private final int pointerToRawData;
        private final int pointerToRelocations;
        private final int pointerToLinenumbers;
        private final int numberOfRelocations;
        private final int numberOfLinenumbers;
        private final int characteristics;

        public SectionHeader(ByteBuffer buffer) {
            byte[] bytes = new byte[8];
            buffer.get(bytes);
            int end = 0;
            for (; end < bytes.length; end++) {
                if (bytes[end] == 0) {
                    break;
                }
            }
            name = new String(bytes, 0, end, StandardCharsets.ISO_8859_1);
            virtualSize = buffer.getInt();
            virtualAddress = buffer.getInt();
            sizeOfRawData = buffer.getInt();
            pointerToRawData = buffer.getInt();
            pointerToRelocations = buffer.getInt();
            pointerToLinenumbers = buffer.getInt();
            numberOfRelocations = getShortAsInt(buffer);
            numberOfLinenumbers = getShortAsInt(buffer);
            characteristics = buffer.getInt();
        }

        private SectionHeader(SectionHeader header, String name){
            this.name = name;
            this.virtualSize = header.virtualSize;
            this.virtualAddress = header.virtualAddress;
            this.sizeOfRawData = header.sizeOfRawData;
            this.pointerToRawData = header.pointerToRawData;
            this.pointerToRelocations = header.pointerToRelocations;
            this.pointerToLinenumbers = header.pointerToLinenumbers;
            this.numberOfRelocations = header.numberOfRelocations;
            this.numberOfLinenumbers = header.numberOfLinenumbers;
            this.characteristics = header.characteristics;
        }

        public String getName() {
            return name;
        }

        public long getVirtualSize() {
            return virtualSize & 0xffffffffL;
        }

        public long getVirtualAddress() {
            return virtualAddress & 0xffffffffL;
        }

        public long getSizeOfRawData() {
            return sizeOfRawData & 0xffffffffL;
        }

        public long getPointerToRawData() {
            return pointerToRawData & 0xffffffffL;
        }

        public long getPointerToRelocations() {
            return pointerToRelocations & 0xffffffffL;
        }

        public long getPointerToLinenumbers() {
            return pointerToLinenumbers & 0xffffffffL;
        }

        public int getNumberOfRelocations() {
            return numberOfRelocations & 0xffff;
        }

        public int getNumberOfLinenumbers() {
            return numberOfLinenumbers & 0xffff;
        }

        public int getCharacteristics() {
            return characteristics;
        }

    }

}

class PEFileException extends RuntimeException {
    public PEFileException(String message) {
        super(message);
    }
}
