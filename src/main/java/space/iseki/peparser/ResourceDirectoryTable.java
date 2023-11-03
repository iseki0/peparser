package space.iseki.peparser;

public record ResourceDirectoryTable(int characteristic,
                                     int timeDateStamp,
                                     short majorVersion,
                                     short minorVersion,
                                     short numberOfNameEntries,
                                     short numberOfIdEntries) {
}
