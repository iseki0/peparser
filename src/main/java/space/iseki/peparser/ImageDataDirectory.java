package space.iseki.peparser;

public record ImageDataDirectory(int virtualAddress, int size) {
    static final ImageDataDirectory ZERO = new ImageDataDirectory(0, 0);
}
