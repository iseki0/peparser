package space.iseki.peparser;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public record ResourcePathSegment(@Nullable String name, int id) {
    public ResourcePathSegment {
    }

    public ResourcePathSegment(@NotNull String name) {
        this(name, 0);
    }

    public ResourcePathSegment(int id) {
        this(null, id);
    }
}
