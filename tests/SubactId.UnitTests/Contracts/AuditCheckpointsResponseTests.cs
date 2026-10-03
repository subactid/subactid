using System.Text.Json;
using SubactId.Core.Audit;
using SubactId.Server.Contracts;
using Xunit;

namespace SubactId.UnitTests.Contracts;

/// <summary>
/// The published shapes of spec sections 7.0 and 7.1. A checkpoint's field names are the keys of
/// the bytes it was signed over, so a holder must be able to rebuild those bytes from what it received.
/// </summary>
public class AuditCheckpointsResponseTests
{
    private static readonly DateTimeOffset ClosedAt = new(2026, 9, 9, 14, 4, 0, 0, TimeSpan.Zero);

    [Fact]
    public void A_full_page_plus_one_yields_the_page_and_next_after_at_its_last_checkpoint()
    {
        var response = AuditCheckpointsResponse.From(Enumerable.Range(1, 4).Select(id => Checkpoint(id)).ToList(), 3);

        Assert.Equal([1, 2, 3], response.Checkpoints.Select(c => c.CheckpointId));
        Assert.Equal(3, response.NextAfter);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(3)]
    public void A_short_or_exactly_full_page_is_the_last_one(int count)
    {
        var response = AuditCheckpointsResponse.From(Enumerable.Range(1, count).Select(id => Checkpoint(id)).ToList(), 3);

        Assert.Equal(count, response.Checkpoints.Count);
        Assert.Null(response.NextAfter);
    }

    [Fact]
    public void A_checkpoint_is_published_field_for_field_as_section_7_0_shows_it()
    {
        var previous = Checkpoint(270);
        var checkpoint = Checkpoint(271, previous, treeSize: 131);

        var json = JsonSerializer.Serialize(AuditCheckpointsResponse.From([checkpoint], 1), SubactIdJson.CreateOptions());

        using var document = JsonDocument.Parse(json);
        Assert.Equal(["checkpoints", "next_after"], document.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal(JsonValueKind.Null, document.RootElement.GetProperty("next_after").ValueKind);
        var published = document.RootElement.GetProperty("checkpoints")[0];
        Assert.Equal(
            ["checkpoint_id", "first_seq", "last_seq", "tree_size", "root_hash", "prev_checkpoint_hash", "closed_at", "kid", "signature"],
            published.EnumerateObject().Select(p => p.Name));
        Assert.Equal((271L, 10380L, 10512L, 131L), (published.GetProperty("checkpoint_id").GetInt64(), published.GetProperty("first_seq").GetInt64(), published.GetProperty("last_seq").GetInt64(), published.GetProperty("tree_size").GetInt64()));
        Assert.Equal(Convert.ToHexStringLower(checkpoint.RootHash.Span), published.GetProperty("root_hash").GetString());
        Assert.Equal(Convert.ToHexStringLower(AuditCheckpointHash.LinkHash(previous)), published.GetProperty("prev_checkpoint_hash").GetString());
        Assert.Equal("2026-09-09T14:04:00.000Z", published.GetProperty("closed_at").GetString());
        Assert.Equal("key-2026-09", published.GetProperty("kid").GetString());
        Assert.Equal(Convert.ToHexStringLower(checkpoint.Signature.Span), published.GetProperty("signature").GetString());
    }

    /// <summary>The bytes a holder rebuilds from the published fields are the bytes that were signed.</summary>
    [Fact]
    public void The_published_fields_rebuild_the_signed_bytes_exactly()
    {
        var checkpoint = Checkpoint(271, Checkpoint(270), treeSize: 131);

        var json = JsonSerializer.Serialize(AuditCheckpointPayload.From(checkpoint), SubactIdJson.CreateOptions());

        using var document = JsonDocument.Parse(json);
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            string[] signedFields = ["checkpoint_id", "closed_at", "first_seq", "kid", "last_seq", "prev_checkpoint_hash", "root_hash", "tree_size"];
            writer.WriteStartObject();
            foreach (var field in signedFields)
            {
                writer.WritePropertyName(field);
                document.RootElement.GetProperty(field).WriteTo(writer);
            }

            writer.WriteEndObject();
        }

        Assert.Equal(AuditCheckpointHash.SignedBytes(checkpoint), buffer.ToArray());
    }

    /// <summary>
    /// The first checkpoint's link is an explicit null, not a missing key or an empty string, because
    /// the signed bytes carry <c>"prev_checkpoint_hash":null</c>.
    /// </summary>
    [Fact]
    public void The_first_checkpoint_publishes_an_explicit_null_link()
    {
        var json = JsonSerializer.Serialize(AuditCheckpointPayload.From(Checkpoint(1)), SubactIdJson.CreateOptions());

        using var document = JsonDocument.Parse(json);
        Assert.Equal(JsonValueKind.Null, document.RootElement.GetProperty("prev_checkpoint_hash").ValueKind);
    }

    [Fact]
    public void A_proof_is_published_as_seq_checkpoint_leaf_index_and_audit_path()
    {
        var proof = new AuditProofResponse
        {
            Seq = 10428,
            Checkpoint = AuditCheckpointPayload.From(Checkpoint(271)),
            LeafIndex = 48,
            AuditPath = [Convert.ToHexStringLower(Bytes(0xa1)), Convert.ToHexStringLower(Bytes(0xc3))],
        };

        var json = JsonSerializer.Serialize(proof, SubactIdJson.CreateOptions());

        using var document = JsonDocument.Parse(json);
        Assert.Equal(["seq", "checkpoint", "leaf_index", "audit_path"], document.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal((10428L, 48L), (document.RootElement.GetProperty("seq").GetInt64(), document.RootElement.GetProperty("leaf_index").GetInt64()));
        Assert.Equal(271, document.RootElement.GetProperty("checkpoint").GetProperty("checkpoint_id").GetInt64());
        Assert.Equal(2, document.RootElement.GetProperty("audit_path").GetArrayLength());
        Assert.Matches("^[0-9a-f]{64}$", document.RootElement.GetProperty("audit_path")[0].GetString());
    }

    /// <summary>A one-record checkpoint's proof has no siblings, and that is a complete proof.</summary>
    [Fact]
    public void A_proof_inside_a_one_record_checkpoint_has_an_empty_path_not_a_missing_one()
    {
        var proof = new AuditProofResponse { Seq = 1, Checkpoint = AuditCheckpointPayload.From(Checkpoint(1)), LeafIndex = 0, AuditPath = [] };

        var json = JsonSerializer.Serialize(proof, SubactIdJson.CreateOptions());

        using var document = JsonDocument.Parse(json);
        Assert.Equal(JsonValueKind.Array, document.RootElement.GetProperty("audit_path").ValueKind);
        Assert.Equal(0, document.RootElement.GetProperty("audit_path").GetArrayLength());
    }

    private static AuditCheckpoint Checkpoint(long id, AuditCheckpoint? previous = null, long treeSize = 133) =>
        new(
            id,
            FirstSeq: 10380,
            LastSeq: 10512,
            treeSize,
            RootHash: Bytes(0x4e),
            previous is null ? null : (ReadOnlyMemory<byte>?)AuditCheckpointHash.LinkHash(previous),
            ClosedAt,
            "key-2026-09",
            Signature: Bytes(0x3b, 64));

    private static byte[] Bytes(byte value, int length = 32) => Enumerable.Repeat(value, length).ToArray();
}
