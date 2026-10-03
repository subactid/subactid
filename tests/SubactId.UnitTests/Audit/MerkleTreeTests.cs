using System.Security.Cryptography;
using System.Text;
using SubactId.Core.Audit;
using Xunit;

namespace SubactId.UnitTests.Audit;

/// <summary>
/// The tree the ledger is sealed with, tested against the shapes RFC 6962 defines. A proof must
/// verify in any reader that follows the RFC.
/// </summary>
public class MerkleTreeTests
{
    [Fact]
    public void A_leaf_is_sha256_of_a_zero_byte_and_the_content()
    {
        var content = Encoding.UTF8.GetBytes("""{"event":"token.issued"}""");
        byte[] prefixed = [0x00, .. content];

        Assert.Equal(SHA256.HashData(prefixed), MerkleTree.Leaf(content));
    }

    [Fact]
    public void A_node_is_sha256_of_a_one_byte_and_both_children()
    {
        var left = Hash(1);
        var right = Hash(2);
        byte[] prefixed = [0x01, .. left, .. right];

        Assert.Equal(SHA256.HashData(prefixed), MerkleTree.Node(left, right));
    }

    /// <summary>
    /// The prefixes stop an interior node being passed off as a leaf, which would let a tree claim a
    /// record it does not hold.
    /// </summary>
    [Fact]
    public void A_leaf_over_two_hashes_is_not_the_node_over_them()
    {
        var left = Hash(1);
        var right = Hash(2);
        byte[] joined = [.. left, .. right];

        Assert.NotEqual(MerkleTree.Leaf(joined), MerkleTree.Node(left, right));
    }

    [Fact]
    public void A_one_leaf_tree_is_that_leaf_and_it_is_not_the_callers_array()
    {
        var leaf = Hash(7);
        var leaves = new[] { leaf };

        var root = MerkleTree.Root(leaves);

        Assert.Equal(leaf, root);
        root[0] ^= 0xFF;
        Assert.Equal(leaf, leaves[0]);
    }

    /// <summary>RFC 6962 splits at the largest power of two strictly below the leaf count, so the left subtree is always perfect.</summary>
    [Theory]
    [InlineData(2, 1)]
    [InlineData(3, 2)]
    [InlineData(4, 2)]
    [InlineData(5, 4)]
    [InlineData(7, 4)]
    [InlineData(8, 4)]
    [InlineData(9, 8)]
    [InlineData(16, 8)]
    [InlineData(17, 16)]
    public void The_split_is_the_largest_power_of_two_below_the_count(int count, int expected) =>
        Assert.Equal(expected, MerkleTree.SplitPoint(count));

    /// <summary>
    /// The shape for small sizes: an odd leaf is carried up as itself, not doubled, and joins on the right.
    /// </summary>
    [Fact]
    public void The_shape_is_the_rfcs_and_not_a_promoted_odd_leaf()
    {
        var leaves = Enumerable.Range(0, 5).Select(i => Hash((byte)i)).ToList();

        Assert.Equal(MerkleTree.Node(leaves[0], leaves[1]), MerkleTree.Root(leaves.Take(2).ToList()));
        Assert.Equal(
            MerkleTree.Node(MerkleTree.Node(leaves[0], leaves[1]), leaves[2]),
            MerkleTree.Root(leaves.Take(3).ToList()));
        Assert.Equal(
            MerkleTree.Node(MerkleTree.Node(leaves[0], leaves[1]), MerkleTree.Node(leaves[2], leaves[3])),
            MerkleTree.Root(leaves.Take(4).ToList()));
        Assert.Equal(
            MerkleTree.Node(MerkleTree.Node(MerkleTree.Node(leaves[0], leaves[1]), MerkleTree.Node(leaves[2], leaves[3])), leaves[4]),
            MerkleTree.Root(leaves));
    }

    /// <summary>
    /// Every leaf of every tree size has a path that folds back to the root. Sizes are walked, not
    /// sampled, because the shape changes at each power of two.
    /// </summary>
    [Fact]
    public void Every_leaf_of_every_size_up_to_thirty_three_proves_itself()
    {
        for (var size = 1; size <= 33; size++)
        {
            var leaves = Enumerable.Range(0, size).Select(i => Hash((byte)i)).ToList();
            var root = MerkleTree.Root(leaves);
            for (var index = 0; index < size; index++)
            {
                var path = MerkleTree.Path(leaves, index);
                Assert.Equal(root, Folded(leaves[index], index, size, path));
            }
        }
    }

    [Fact]
    public void A_one_leaf_tree_proves_itself_with_an_empty_path()
    {
        var leaf = Hash(3);

        Assert.Empty(MerkleTree.Path([leaf], 0));
        Assert.Equal(leaf, Folded(leaf, 0, 1, []));
    }

    [Fact]
    public void A_proof_of_the_wrong_leaf_or_the_wrong_position_does_not_reach_the_root()
    {
        var leaves = Enumerable.Range(0, 6).Select(i => Hash((byte)i)).ToList();
        var root = MerkleTree.Root(leaves);
        var path = MerkleTree.Path(leaves, 2);

        Assert.Equal(root, Folded(leaves[2], 2, 6, path));
        Assert.NotEqual(root, Folded(Hash(99), 2, 6, path));
        Assert.NotEqual(root, Folded(leaves[2], 3, 6, path));

        var tampered = path.Select(step => step.ToArray()).ToList();
        tampered[0][0] ^= 0xFF;
        Assert.NotEqual(root, Folded(leaves[2], 2, 6, tampered));
    }

    /// <summary>A path of the wrong length for the claimed size is refused.</summary>
    [Fact]
    public void A_path_that_does_not_fit_the_tree_it_claims_is_rejected()
    {
        var leaves = Enumerable.Range(0, 8).Select(i => Hash((byte)i)).ToList();
        var path = MerkleTree.Path(leaves, 5);

        Assert.Null(MerkleTree.RootFromPath(leaves[5], 5, 8, path.Take(2).ToList()));
        Assert.Null(MerkleTree.RootFromPath(leaves[5], 5, 8, [.. path, Hash(9)]));
        Assert.Null(MerkleTree.RootFromPath(leaves[5], 5, 4, path));
        Assert.Null(MerkleTree.RootFromPath(leaves[5], 8, 8, path));
        Assert.Null(MerkleTree.RootFromPath(leaves[5], -1, 8, path));
        Assert.Null(MerkleTree.RootFromPath(leaves[5], 0, 0, []));
        Assert.Null(MerkleTree.RootFromPath(new byte[16], 0, 1, []));
        Assert.Null(MerkleTree.RootFromPath(leaves[5], 5, 8, [.. path.Take(path.Count - 1), new byte[16]]));
    }

    /// <summary>Order is part of the root: the same records in another order make another tree.</summary>
    [Fact]
    public void Reordering_the_leaves_changes_the_root()
    {
        var leaves = Enumerable.Range(0, 4).Select(i => Hash((byte)i)).ToList();

        Assert.NotEqual(MerkleTree.Root(leaves), MerkleTree.Root([leaves[1], leaves[0], leaves[2], leaves[3]]));
    }

    [Fact]
    public void An_empty_tree_is_refused_because_an_empty_range_is_never_sealed()
    {
        Assert.Throws<ArgumentException>(() => MerkleTree.Root([]));
        Assert.Throws<ArgumentOutOfRangeException>(() => MerkleTree.SplitPoint(1));
        Assert.Throws<ArgumentOutOfRangeException>(() => MerkleTree.Path([Hash(1)], 1));
    }

    /// <summary>The root a path implies, or an empty array when it implies none.</summary>
    private static byte[] Folded(byte[] leaf, long index, long treeSize, IReadOnlyList<byte[]> path) =>
        MerkleTree.RootFromPath(leaf, index, treeSize, path) ?? [];

    private static byte[] Hash(byte seed) => SHA256.HashData(new[] { seed });
}
