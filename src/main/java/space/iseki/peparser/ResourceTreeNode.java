package space.iseki.peparser;

import org.jetbrains.annotations.Nullable;

import java.util.List;

public record ResourceTreeNode(List<ResourceTreeNode> children,
                               @Nullable String name,
                               int id,
                               @Nullable ResourceData resourceData) {
    void buildString(StringBuilder builder, int off) {
        assert off >= 0;
        builder.append("  ".repeat(off));
        if (name != null) {
            builder.append("Name: ").append(name);
        } else {
            builder.append("ID: ").append(id);
        }
        if (resourceData != null) builder.append(' ').append(resourceData);
        builder.append('\n');
        for (ResourceTreeNode child : children) {
            child.buildString(builder, off + 1);
        }
    }

    @Override
    public String toString() {
        var b = new StringBuilder();
        buildString(b, 0);
        return b.toString();
    }
}


