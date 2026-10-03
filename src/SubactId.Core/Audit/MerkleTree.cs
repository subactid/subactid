using System.Numerics;
using System.Security.Cryptography;

namespace SubactId.Core.Audit;

/// <summary>
/// The RFC 6962 Merkle tree that seals the ledger. A leaf is
/// <c>sha256(0x00 || canonical_json(record))</c>, an interior node is
/// <c>sha256(0x01 || left || right)</c>, and a tree of <c>n</c> leaves splits at the largest
/// power of two below <c>n</c>. Pure functions for roots, audit paths and path verification.
/// <para>
/// The prefixes stop an interior node from being passed off as a leaf. Proofs are compatible
/// with Certificate Transparency implementations.
/// </para>
/// </summary>
public static class MerkleTree
{
    /// <summary>Length of a node or leaf hash in bytes.</summary>
    public const int HashLength = 32;

    /// <summary>Domain separator in front of a leaf's content.</summary>
    public const byte LeafPrefix = 0x00;

    /// <summary>Domain separator in front of an interior node's two children.</summary>
    public const byte NodePrefix = 0x01;

    /// <summary>The leaf hash of <paramref name="content"/>: <c>sha256(0x00 || content)</c>.</summary>
    /// <param name="content">The record's canonical JSON.</param>
    public static byte[] Leaf(ReadOnlySpan<byte> content)
    {
        var input = new byte[content.Length + 1];
        input[0] = LeafPrefix;
        content.CopyTo(input.AsSpan(1));
        return SHA256.HashData(input);
    }

    /// <summary>The interior node over two children: <c>sha256(0x01 || left || right)</c>.</summary>
    /// <param name="left">The left child's hash.</param>
    /// <param name="right">The right child's hash.</param>
    public static byte[] Node(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        var input = new byte[1 + left.Length + right.Length];
        input[0] = NodePrefix;
        left.CopyTo(input.AsSpan(1));
        right.CopyTo(input.AsSpan(1 + left.Length));
        return SHA256.HashData(input);
    }

    /// <summary>The root over <paramref name="leaves"/>, in the order given.</summary>
    /// <param name="leaves">Leaf hashes, at least one.</param>
    /// <exception cref="ArgumentException">There are no leaves.</exception>
    public static byte[] Root(IReadOnlyList<byte[]> leaves)
    {
        ArgumentNullException.ThrowIfNull(leaves);

        if (leaves.Count == 0)
        {
            throw new ArgumentException("A Merkle tree needs at least one leaf; an empty range is not sealed.", nameof(leaves));
        }

        // A one-leaf root is a copy of the leaf, so later writes to the caller's array cannot change it.
        return leaves.Count == 1 ? leaves[0].AsSpan().ToArray() : RootOf(leaves, 0, leaves.Count);
    }

    /// <summary>
    /// The audit path for the leaf at <paramref name="index"/>: the sibling hashes, closest first,
    /// from the leaf to the root. A one-leaf tree has an empty path, which is a valid proof.
    /// </summary>
    /// <param name="leaves">Leaf hashes, at least one.</param>
    /// <param name="index">Position of the leaf being proved.</param>
    public static IReadOnlyList<byte[]> Path(IReadOnlyList<byte[]> leaves, int index)
    {
        ArgumentNullException.ThrowIfNull(leaves);
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, leaves.Count);

        var path = new List<byte[]>();
        PathOf(leaves, 0, leaves.Count, index, path);
        return path;
    }

    /// <summary>
    /// The root <paramref name="path"/> implies for the leaf at <paramref name="index"/> of a tree
    /// of <paramref name="treeSize"/> leaves, or <c>null</c> when the proof is not well formed for
    /// that position and size. The caller compares the result with the signed root.
    /// </summary>
    /// <param name="leaf">The leaf hash being proved.</param>
    /// <param name="index">Position of the leaf.</param>
    /// <param name="treeSize">Leaves in the tree the root was taken over.</param>
    /// <param name="path">The audit path, closest sibling first.</param>
    public static byte[]? RootFromPath(ReadOnlySpan<byte> leaf, long index, long treeSize, IReadOnlyList<byte[]> path)
    {
        ArgumentNullException.ThrowIfNull(path);

        if (leaf.Length != HashLength || treeSize <= 0 || index < 0 || index >= treeSize)
        {
            return null;
        }

        foreach (var sibling in path)
        {
            if (sibling is not { Length: HashLength })
            {
                return null;
            }
        }

        // RFC 6962 section 2.1.1. fn is the leaf index and sn the last index, shifted up a level
        // each step. A path that is too short or too long is rejected.
        var fn = index;
        var sn = treeSize - 1;
        var root = leaf.ToArray();
        foreach (var sibling in path)
        {
            if (sn == 0)
            {
                return null;
            }

            if ((fn & 1) == 1 || fn == sn)
            {
                root = Node(sibling, root);
                while (fn != 0 && (fn & 1) == 0)
                {
                    fn >>= 1;
                    sn >>= 1;
                }
            }
            else
            {
                root = Node(root, sibling);
            }

            fn >>= 1;
            sn >>= 1;
        }

        return sn == 0 ? root : null;
    }

    /// <summary>
    /// Where a tree of <paramref name="count"/> leaves splits: the largest power of two below it.
    /// </summary>
    /// <param name="count">Leaves in the tree, more than one.</param>
    public static int SplitPoint(int count)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(count, 2);

        return 1 << BitOperations.Log2((uint)(count - 1));
    }

    private static byte[] RootOf(IReadOnlyList<byte[]> leaves, int start, int count)
    {
        if (count == 1)
        {
            return leaves[start];
        }

        var split = SplitPoint(count);
        return Node(RootOf(leaves, start, split), RootOf(leaves, start + split, count - split));
    }

    private static void PathOf(IReadOnlyList<byte[]> leaves, int start, int count, int index, List<byte[]> path)
    {
        if (count == 1)
        {
            return;
        }

        var split = SplitPoint(count);
        if (index < split)
        {
            PathOf(leaves, start, split, index, path);
            path.Add(RootOf(leaves, start + split, count - split));
        }
        else
        {
            PathOf(leaves, start + split, count - split, index - split, path);
            path.Add(RootOf(leaves, start, split));
        }
    }
}
