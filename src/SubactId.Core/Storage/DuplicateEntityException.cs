namespace SubactId.Core.Storage;

/// <summary>Thrown when a repository is asked to add an entity whose key already exists.</summary>
public sealed class DuplicateEntityException : Exception
{
    /// <summary>Creates the exception.</summary>
    /// <param name="entity">The kind of entity, for example <c>agent</c>.</param>
    /// <param name="key">The duplicated key. Must never be a secret.</param>
    public DuplicateEntityException(string entity, string key)
        : base($"A {entity} with key '{key}' already exists.")
    {
        Entity = entity;
        Key = key;
    }

    /// <summary>The kind of entity.</summary>
    public string Entity { get; }

    /// <summary>The duplicated key.</summary>
    public string Key { get; }
}
