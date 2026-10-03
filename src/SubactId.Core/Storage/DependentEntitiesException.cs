namespace SubactId.Core.Storage;

/// <summary>Thrown when a repository is asked to delete an entity that other entities still refer to.</summary>
public sealed class DependentEntitiesException : Exception
{
    /// <summary>Creates the exception.</summary>
    /// <param name="entity">The kind of entity, for example <c>agent</c>.</param>
    /// <param name="key">Its key. Must never be a secret.</param>
    public DependentEntitiesException(string entity, string key)
        : base($"The {entity} with key '{key}' is still referenced by other records.")
    {
        Entity = entity;
        Key = key;
    }

    /// <summary>The kind of entity.</summary>
    public string Entity { get; }

    /// <summary>Its key.</summary>
    public string Key { get; }
}
