package space.iseki.peparser;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.List;

/**
 * Represents a resource in the resource tree({@code .rsrc} section)
 *
 * @param children the list must be immutable, for leaf node, the field will be an empty list
 * @param name will be null if the node hasn't a name(ID resource)
 * @param id will be zero if the node has a name(Name resource)
 * @param resourceData the resource data record, will be null if the node is not a leaf
 */
public record ResourceTreeNode(@NotNull List<@NotNull ResourceTreeNode> children,
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

