using System.Buffers.Binary;
using Ipa.Collectors.ActiveDirectory.Discovery;
using Ipa.Contracts.Directory;
using Ipa.Contracts.Evidence;

namespace Ipa.Collectors.ActiveDirectory.Normalisation;

/// <summary>One access-control entry recovered from a binary security descriptor.</summary>
public sealed record ParsedAce
{
    public required string TrusteeSid { get; init; }
    public required uint AccessMask { get; init; }
    public required bool IsDeny { get; init; }
    public required bool IsInherited { get; init; }

    /// <summary>Object type GUID for an object-specific entry, otherwise null.</summary>
    public string? ObjectTypeGuid { get; init; }

    /// <summary>Inherited object type GUID for an object-specific entry, otherwise null.</summary>
    public string? InheritedObjectTypeGuid { get; init; }
}

/// <summary>A parsed security descriptor.</summary>
public sealed record ParsedSecurityDescriptor
{
    public string? OwnerSid { get; init; }
    public string? GroupSid { get; init; }
    public IReadOnlyList<ParsedAce> DiscretionaryAces { get; init; } = [];

    /// <summary>True when the descriptor's discretionary list is absent, meaning full access.</summary>
    public bool HasNullDacl { get; init; }
}

/// <summary>
/// Parses Windows security descriptors from their self-relative binary form.
/// </summary>
/// <remarks>
/// The parser is implemented directly against the documented layout rather than through a
/// platform security type, so that the same descriptor bytes produce identical normalised evidence
/// when the assessment runs on Windows and on Linux.
/// </remarks>
public static class SecurityDescriptorParser
{
    // Directory-service access mask bits.
    private const uint CreateChild = 0x00000001;
    private const uint DeleteChild = 0x00000002;
    private const uint Self = 0x00000008;
    private const uint WriteProperty = 0x00000020;
    private const uint ControlAccess = 0x00000100;
    private const uint WriteDacl = 0x00040000;
    private const uint WriteOwner = 0x00080000;
    private const uint GenericAll = 0x10000000;
    private const uint GenericWrite = 0x40000000;

    // Access-control entry types.
    private const byte AccessAllowedAce = 0x00;
    private const byte AccessDeniedAce = 0x01;
    private const byte AccessAllowedObjectAce = 0x05;
    private const byte AccessDeniedObjectAce = 0x06;

    private const byte InheritedAceFlag = 0x10;

    private const uint ObjectTypePresent = 0x00000001;
    private const uint InheritedObjectTypePresent = 0x00000002;

    /// <summary>Control flag indicating the discretionary access-control list is present.</summary>
    private const ushort DaclPresent = 0x0004;

    /// <summary>Parses a self-relative security descriptor. Returns null when the input is malformed.</summary>
    public static ParsedSecurityDescriptor? Parse(ReadOnlySpan<byte> descriptor)
    {
        if (descriptor.Length < 20)
        {
            return null;
        }

        var control = BinaryPrimitives.ReadUInt16LittleEndian(descriptor[2..]);
        var ownerOffset = BinaryPrimitives.ReadUInt32LittleEndian(descriptor[4..]);
        var groupOffset = BinaryPrimitives.ReadUInt32LittleEndian(descriptor[8..]);
        var daclOffset = BinaryPrimitives.ReadUInt32LittleEndian(descriptor[16..]);

        var owner = ReadSid(descriptor, ownerOffset);
        var group = ReadSid(descriptor, groupOffset);

        if ((control & DaclPresent) == 0 || daclOffset == 0)
        {
            return new ParsedSecurityDescriptor
            {
                OwnerSid = owner,
                GroupSid = group,
                HasNullDacl = true,
            };
        }

        var aces = ReadAcl(descriptor, daclOffset);

        return new ParsedSecurityDescriptor
        {
            OwnerSid = owner,
            GroupSid = group,
            DiscretionaryAces = aces,
        };
    }

    /// <summary>Maps a directory access mask onto the rights the rule pack reasons about.</summary>
    public static AdAceRight MapRights(uint accessMask, bool isObjectSpecific, string? objectTypeGuid)
    {
        var rights = AdAceRight.None;

        if ((accessMask & GenericAll) != 0)
        {
            rights |= AdAceRight.GenericAll;
        }

        if ((accessMask & GenericWrite) != 0)
        {
            rights |= AdAceRight.GenericWrite;
        }

        if ((accessMask & WriteDacl) != 0)
        {
            rights |= AdAceRight.WriteDacl;
        }

        if ((accessMask & WriteOwner) != 0)
        {
            rights |= AdAceRight.WriteOwner;
        }

        if ((accessMask & WriteProperty) != 0)
        {
            rights |= AdAceRight.WriteProperty;
        }

        if ((accessMask & CreateChild) != 0)
        {
            rights |= AdAceRight.CreateChild;
        }

        if ((accessMask & DeleteChild) != 0)
        {
            rights |= AdAceRight.DeleteChild;
        }

        if ((accessMask & Self) != 0)
        {
            rights |= AdAceRight.Self;
        }

        if ((accessMask & ControlAccess) != 0)
        {
            // A control-access entry with no object type grants every extended right; one that
            // names an object type grants only that right.
            rights |= isObjectSpecific && objectTypeGuid is not null
                ? AdAceRight.ExtendedRight
                : AdAceRight.AllExtendedRights;
        }

        return rights;
    }

    /// <summary>Returns the friendly name of a well-known extended right, when it has one.</summary>
    public static string? DescribeExtendedRight(string? objectTypeGuid) => objectTypeGuid?.ToLowerInvariant() switch
    {
        ExtendedRights.ReplicatingDirectoryChanges => "DS-Replication-Get-Changes",
        ExtendedRights.ReplicatingDirectoryChangesAll => "DS-Replication-Get-Changes-All",
        ExtendedRights.ReplicatingDirectoryChangesInFilteredSet => "DS-Replication-Get-Changes-In-Filtered-Set",
        ExtendedRights.ResetPassword => "User-Force-Change-Password",
        ExtendedRights.CertificateEnrollment => "Certificate-Enrollment",
        ExtendedRights.CertificateAutoEnrollment => "Certificate-AutoEnrollment",
        _ => null,
    };

    private static IReadOnlyList<ParsedAce> ReadAcl(ReadOnlySpan<byte> descriptor, uint aclOffset)
    {
        if (aclOffset + 8 > descriptor.Length)
        {
            return [];
        }

        var acl = descriptor[(int)aclOffset..];
        var aceCount = BinaryPrimitives.ReadUInt16LittleEndian(acl[4..]);
        var aces = new List<ParsedAce>(aceCount);

        var offset = 8;

        for (var index = 0; index < aceCount; index++)
        {
            if (offset + 4 > acl.Length)
            {
                break;
            }

            var aceType = acl[offset];
            var aceFlags = acl[offset + 1];
            var aceSize = BinaryPrimitives.ReadUInt16LittleEndian(acl[(offset + 2)..]);

            if (aceSize < 8 || offset + aceSize > acl.Length)
            {
                break;
            }

            var body = acl.Slice(offset, aceSize);
            var parsed = ParseAce(aceType, aceFlags, body);

            if (parsed is not null)
            {
                aces.Add(parsed);
            }

            offset += aceSize;
        }

        return aces;
    }

    private static ParsedAce? ParseAce(byte aceType, byte aceFlags, ReadOnlySpan<byte> ace)
    {
        var isDeny = aceType is AccessDeniedAce or AccessDeniedObjectAce;
        var isObjectAce = aceType is AccessAllowedObjectAce or AccessDeniedObjectAce;

        if (aceType is not (AccessAllowedAce or AccessDeniedAce or AccessAllowedObjectAce or AccessDeniedObjectAce))
        {
            // Audit, alarm and conditional entries are not part of the discretionary model the
            // rule pack evaluates, and are skipped rather than misreported.
            return null;
        }

        if (ace.Length < 12)
        {
            return null;
        }

        var accessMask = BinaryPrimitives.ReadUInt32LittleEndian(ace[4..]);
        var offset = 8;
        string? objectType = null;
        string? inheritedObjectType = null;

        if (isObjectAce)
        {
            if (ace.Length < 12)
            {
                return null;
            }

            var objectFlags = BinaryPrimitives.ReadUInt32LittleEndian(ace[offset..]);
            offset += 4;

            if ((objectFlags & ObjectTypePresent) != 0)
            {
                if (offset + 16 > ace.Length)
                {
                    return null;
                }

                objectType = new Guid(ace.Slice(offset, 16)).ToString("d");
                offset += 16;
            }

            if ((objectFlags & InheritedObjectTypePresent) != 0)
            {
                if (offset + 16 > ace.Length)
                {
                    return null;
                }

                inheritedObjectType = new Guid(ace.Slice(offset, 16)).ToString("d");
                offset += 16;
            }
        }

        if (offset >= ace.Length)
        {
            return null;
        }

        var sid = SidConverter.ToString(ace[offset..]);
        if (sid is null)
        {
            return null;
        }

        return new ParsedAce
        {
            TrusteeSid = sid,
            AccessMask = accessMask,
            IsDeny = isDeny,
            IsInherited = (aceFlags & InheritedAceFlag) != 0,
            ObjectTypeGuid = objectType,
            InheritedObjectTypeGuid = inheritedObjectType,
        };
    }

    private static string? ReadSid(ReadOnlySpan<byte> descriptor, uint offset)
    {
        if (offset == 0 || offset + 8 > descriptor.Length)
        {
            return null;
        }

        return SidConverter.ToString(descriptor[(int)offset..]);
    }
}
