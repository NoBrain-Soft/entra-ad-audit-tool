using System.Buffers.Binary;
using Ipa.Collectors.ActiveDirectory.Discovery;
using Ipa.Collectors.ActiveDirectory.Normalisation;
using Ipa.Contracts.Directory;
using Ipa.Contracts.Evidence;
using Xunit;

namespace Ipa.Collectors.Tests;

/// <summary>
/// Golden tests for the security descriptor parser. Descriptors are built byte by byte from the
/// documented self-relative layout so the expectations hold identically on Windows and Linux.
/// </summary>
public sealed class SecurityDescriptorParserTests
{
    private const uint GenericAll = 0x10000000;
    private const uint WriteDacl = 0x00040000;
    private const uint ControlAccess = 0x00000100;
    private const uint WriteProperty = 0x00000020;

    private const byte AccessAllowed = 0x00;
    private const byte AccessDenied = 0x01;
    private const byte AccessAllowedObject = 0x05;

    private static byte[] BuildDescriptor(
        string? ownerSid,
        IReadOnlyList<byte[]> aces,
        bool includeDacl = true)
    {
        var ownerBytes = ownerSid is null ? [] : SidConverter.ToBytes(ownerSid)!;
        var acl = BuildAcl(aces);

        var headerLength = 20;
        var ownerOffset = ownerBytes.Length == 0 ? 0u : (uint)headerLength;
        var daclOffset = includeDacl ? (uint)(headerLength + ownerBytes.Length) : 0u;

        var descriptor = new byte[headerLength + ownerBytes.Length + (includeDacl ? acl.Length : 0)];

        descriptor[0] = 1;                                     // revision
        descriptor[1] = 0;                                     // reserved
        BinaryPrimitives.WriteUInt16LittleEndian(descriptor.AsSpan(2), (ushort)(includeDacl ? 0x8004 : 0x8000));
        BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(4), ownerOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(8), 0);   // group
        BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(12), 0);  // SACL
        BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(16), daclOffset);

        ownerBytes.CopyTo(descriptor.AsSpan(headerLength));

        if (includeDacl)
        {
            acl.CopyTo(descriptor.AsSpan(headerLength + ownerBytes.Length));
        }

        return descriptor;
    }

    private static byte[] BuildAcl(IReadOnlyList<byte[]> aces)
    {
        var total = 8 + aces.Sum(ace => ace.Length);
        var acl = new byte[total];

        acl[0] = 4; // revision
        BinaryPrimitives.WriteUInt16LittleEndian(acl.AsSpan(2), (ushort)total);
        BinaryPrimitives.WriteUInt16LittleEndian(acl.AsSpan(4), (ushort)aces.Count);

        var offset = 8;
        foreach (var ace in aces)
        {
            ace.CopyTo(acl.AsSpan(offset));
            offset += ace.Length;
        }

        return acl;
    }

    private static byte[] BuildAce(byte type, byte flags, uint mask, string sid, Guid? objectType = null)
    {
        var sidBytes = SidConverter.ToBytes(sid)!;
        var objectPart = objectType is null ? 0 : 4 + 16;
        var size = 8 + objectPart + sidBytes.Length;

        var ace = new byte[size];
        ace[0] = type;
        ace[1] = flags;
        BinaryPrimitives.WriteUInt16LittleEndian(ace.AsSpan(2), (ushort)size);
        BinaryPrimitives.WriteUInt32LittleEndian(ace.AsSpan(4), mask);

        var offset = 8;

        if (objectType is { } guid)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(ace.AsSpan(offset), 1); // object type present
            offset += 4;
            guid.ToByteArray().CopyTo(ace.AsSpan(offset));
            offset += 16;
        }

        sidBytes.CopyTo(ace.AsSpan(offset));
        return ace;
    }

    [Fact]
    public void ParsesOwnerAndSimpleAllowAce()
    {
        var descriptor = BuildDescriptor(
            WellKnownSids.BuiltinAdministrators,
            [BuildAce(AccessAllowed, 0, GenericAll, "S-1-5-21-1-2-3-1105")]);

        var parsed = SecurityDescriptorParser.Parse(descriptor);

        Assert.NotNull(parsed);
        Assert.Equal(WellKnownSids.BuiltinAdministrators, parsed!.OwnerSid);
        var ace = Assert.Single(parsed.DiscretionaryAces);
        Assert.Equal("S-1-5-21-1-2-3-1105", ace.TrusteeSid);
        Assert.False(ace.IsDeny);
        Assert.False(ace.IsInherited);
        Assert.Equal(GenericAll, ace.AccessMask);
    }

    [Fact]
    public void DenyAndInheritedFlagsAreRecovered()
    {
        var descriptor = BuildDescriptor(
            null,
            [BuildAce(AccessDenied, 0x10, WriteDacl, "S-1-5-21-1-2-3-1106")]);

        var ace = Assert.Single(SecurityDescriptorParser.Parse(descriptor)!.DiscretionaryAces);

        Assert.True(ace.IsDeny);
        Assert.True(ace.IsInherited);
    }

    [Fact]
    public void ObjectAceCarriesItsObjectTypeGuid()
    {
        var replication = Guid.Parse(ExtendedRights.ReplicatingDirectoryChangesAll);

        var descriptor = BuildDescriptor(
            null,
            [BuildAce(AccessAllowedObject, 0, ControlAccess, "S-1-5-21-1-2-3-1107", replication)]);

        var ace = Assert.Single(SecurityDescriptorParser.Parse(descriptor)!.DiscretionaryAces);

        Assert.Equal(ExtendedRights.ReplicatingDirectoryChangesAll, ace.ObjectTypeGuid);
        Assert.True(ExtendedRights.IsReplicationRight(ace.ObjectTypeGuid));
        Assert.Equal(
            "DS-Replication-Get-Changes-All",
            SecurityDescriptorParser.DescribeExtendedRight(ace.ObjectTypeGuid));
    }

    [Fact]
    public void ControlAccessWithoutAnObjectTypeGrantsEveryExtendedRight()
    {
        var rights = SecurityDescriptorParser.MapRights(ControlAccess, isObjectSpecific: false, objectTypeGuid: null);

        Assert.True(rights.HasFlag(AdAceRight.AllExtendedRights));
        Assert.False(rights.HasFlag(AdAceRight.ExtendedRight));
    }

    [Fact]
    public void ControlAccessWithAnObjectTypeGrantsOnlyThatRight()
    {
        var rights = SecurityDescriptorParser.MapRights(
            ControlAccess,
            isObjectSpecific: true,
            objectTypeGuid: ExtendedRights.ResetPassword);

        Assert.True(rights.HasFlag(AdAceRight.ExtendedRight));
        Assert.False(rights.HasFlag(AdAceRight.AllExtendedRights));
    }

    [Fact]
    public void MultipleAcesAreParsedInOrder()
    {
        var descriptor = BuildDescriptor(
            null,
            [
                BuildAce(AccessAllowed, 0, GenericAll, "S-1-5-21-1-2-3-1108"),
                BuildAce(AccessAllowed, 0, WriteProperty, "S-1-5-21-1-2-3-1109"),
                BuildAce(AccessDenied, 0, WriteDacl, "S-1-5-21-1-2-3-1110"),
            ]);

        var parsed = SecurityDescriptorParser.Parse(descriptor)!;

        Assert.Equal(3, parsed.DiscretionaryAces.Count);
        Assert.Equal("S-1-5-21-1-2-3-1108", parsed.DiscretionaryAces[0].TrusteeSid);
        Assert.Equal("S-1-5-21-1-2-3-1110", parsed.DiscretionaryAces[2].TrusteeSid);
    }

    [Fact]
    public void AbsentDaclIsReportedAsNullNotEmpty()
    {
        var descriptor = BuildDescriptor(WellKnownSids.BuiltinAdministrators, [], includeDacl: false);

        var parsed = SecurityDescriptorParser.Parse(descriptor)!;

        Assert.True(parsed.HasNullDacl);
        Assert.Empty(parsed.DiscretionaryAces);
    }

    [Fact]
    public void MalformedDescriptorReturnsNull()
    {
        Assert.Null(SecurityDescriptorParser.Parse([1, 0, 4]));
        Assert.Null(SecurityDescriptorParser.Parse(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void TruncatedAceStopsParsingWithoutThrowing()
    {
        var descriptor = BuildDescriptor(
            null,
            [BuildAce(AccessAllowed, 0, GenericAll, "S-1-5-21-1-2-3-1111")]);

        var truncated = descriptor[..(descriptor.Length - 6)];

        var parsed = SecurityDescriptorParser.Parse(truncated);

        Assert.NotNull(parsed);
        Assert.Empty(parsed!.DiscretionaryAces);
    }

    [Theory]
    [InlineData("S-1-5-32-544")]
    [InlineData("S-1-5-21-3623811015-3361044348-30300820-1013")]
    [InlineData("S-1-1-0")]
    [InlineData("S-1-5-18")]
    public void SidRoundTripsThroughBinaryForm(string sid)
    {
        var bytes = SidConverter.ToBytes(sid);

        Assert.NotNull(bytes);
        Assert.Equal(sid, SidConverter.ToString(bytes));
    }

    [Fact]
    public void InvalidSidStringsAreRejected()
    {
        Assert.Null(SidConverter.ToBytes("not-a-sid"));
        Assert.Null(SidConverter.ToBytes(string.Empty));
        Assert.Null(SidConverter.ToString([1, 2]));
    }

    [Fact]
    public void RidAndDomainAreExtractedFromASid()
    {
        Assert.Equal(512, WellKnownSids.GetRid("S-1-5-21-1-2-3-512"));
        Assert.Equal("S-1-5-21-1-2-3", WellKnownSids.GetDomainSid("S-1-5-21-1-2-3-512"));
        Assert.Null(WellKnownSids.GetRid(null));
    }
}
