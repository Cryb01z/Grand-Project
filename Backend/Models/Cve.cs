// ReSharper disable UnusedMember.Global
// ReSharper disable ClassNeverInstantiated.Global

using System.Text.Json.Serialization;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

#pragma warning disable CS8618 // Non-nullable field

namespace ASM_Backend.Models;

public class CvssDataV3
{
    /// <summary>
    /// CVSS Version
    /// </summary>
    public string Version { get; set; }
    public string VectorString { get; set; }

    public string? AttackVector { get; set; }
    public string? AttackComplexity { get; set; }
    
    public string? PrivilegesRequired { get; set; }
    public string? UserInteraction { get; set; }
    public string? Scope { get; set; }
    
    public string? ConfidentialityImpact { get; set; }
    public string? IntegrityImpact { get; set; }
    public string? AvailabilityImpact { get; set; }
    
    public double BaseScore { get; set; }
    public string BaseSeverity { get; set; }
}

public class CvssDataV2
{
    /// <summary>
    /// CVSS Version
    /// </summary>
    public string Version { get; set; }
    public string VectorString { get; set; }

    public string? AccessVector { get; set; }
    public string? AccessComplexity { get; set; }
    
    public string? Authentication { get; set; }
    
    public string? ConfidentialityImpact { get; set; }
    public string? IntegrityImpact { get; set; }
    public string? AvailabilityImpact { get; set; }
    
    public double BaseScore { get; set; }
}

public class CvssV2
{
    public string Source { get; set; }
    public string Type { get; set; }
    public CvssDataV2 CvssData { get; set; }
    public string? BaseSeverity { get; set; }
    public double? ExploitabilityScore { get; set; }
    public double? ImpactScore { get; set; }
    public bool? ObtainAllPrivilege { get; set; }
    public bool? ObtainUserPrivilege { get; set; }
    public bool? ObtainOtherPrivilege { get; set; }
    public bool? UserInteractionRequired { get; set; }
}

public class CvssV3
{
    public string Source { get; set; }
    public string Type { get; set; }
    public CvssDataV3 CvssData { get; set; }
    public double? ExploitabilityScore { get; set; }
    public double? ImpactScore { get; set; }
}

/// <summary>
/// CPE match string or range
/// </summary>
public class CpeMatch
{
    public bool Vulnerable { get; set; }
    public string Criteria { get; set; }
    public string MatchCriteriaId { get; set; }
}

/// <summary>
/// Defines a configuration node in an NVD applicability statement.
/// </summary>
public class Node
{
    public string Operator { get; set; }
    public bool? Negate { get; set; }
    public List<CpeMatch> CpeMatch { get; set; }
}

public class Config
{
    public string? Operator { get; set; }
    public List<Node> Nodes { get; set; }
}

public class Weakness
{
    public string Source { get; set; }
    public string Type { get; set; }
    public List<Description> Description { get; set; }
}

public class Metrics
{
    /// <summary>
    /// CVSS V3.1 score.
    /// </summary>
    public List<CvssV3>? CvssMetricV31 { get; set; }

    /// <summary>
    /// CVSS V3.0 score.
    /// </summary>
    public List<CvssV3>? CvssMetricV30 { get; set; }

    /// <summary>
    /// CVSS V2.0 score.
    /// </summary>
    public List<CvssV2>? CvssMetricV2 { get; set; }
}

public class Reference
{
    public string Url { get; set; }
    public string? Source { get; set; }
    public List<string>? Tags { get; set; }
}

public class Description
{
    public string Lang { get; set; }
    public string Value { get; set; }
}

public class Detail
{
    public string Action { get; set; }
    public string Type { get; set; }
    public string OldValue { get; set; }
    public string NewValue { get; set; }
}

public class Change
{
    [BsonIgnore]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string CveId { get; set; }
    [BsonGuidRepresentation(GuidRepresentation.CSharpLegacy)]
    public Guid CveChangeId { get; set; }
    public string EventName { get; set; }
    public DateTime Created { get; set; }
    public List<Detail> Details { get; set; }
}

public class Cve
{
    public string Id { get; set; }
    public string? SourceIdentifier { get; set; }
    public string? VulnStatus { get; set; }
    public DateTime Published { get; set; }
    public DateTime LastModified { get; set; }
    
    public List<Description> Descriptions { get; set; }
    public List<Reference> References { get; set; }

    /// <summary>
    /// Metric scores for a vulnerability as found on NVD.
    /// </summary>
    public Metrics? Metrics { get; set; }

    public List<Weakness>? Weaknesses { get; set; }
    public List<Config>? Configurations { get; set; }
    
    [BsonIgnoreIfNull]
    public List<Change>? Changes { get; set; } = [];
}

public class CveVulnerability
{
    public Cve Cve { get; set; }
}

public class NvdCveFeed
{
    public int ResultsPerPage { get; set; }
    public int StartIndex { get; set; }
    public int TotalResults { get; set; }
    public string Format { get; set; }
    public string Version { get; set; }
    public DateTime Timestamp { get; set; }

    /// <summary>
    /// NVD feed array of CVE
    /// </summary>
    public List<CveVulnerability> Vulnerabilities { get; set; }
}

public class DefChange
{
    public Change Change { get; set; }
}

public class NvdCveChangeFeed
{
    public int ResultsPerPage { get; set; }
    public int StartIndex { get; set; }
    public int TotalResults { get; set; }

    public string Format { get; set; }
    public string Version { get; set; }
    public DateTime Timestamp { get; set; }

    /// <summary>
    /// Array of CVE Changes
    /// </summary>
    public List<DefChange> CveChanges { get; set; }
}