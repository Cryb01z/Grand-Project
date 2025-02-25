#pragma warning disable CS8618 // Non-nullable field

using MongoDB.Bson;
using System.Text.Json.Serialization;

using ASM_Backend.Utilities;
using MongoDB.Bson.Serialization.Attributes;

namespace ASM_Backend.Models;

public abstract class Request
{
    public string Method { get; set; }
    public string Uri { get; set; }
}

public abstract class Response
{
    public int StatusCode { get; set; }
    public string StatusReason { get; set; }
    public string HeaderLocation { get; set; }
    public string HtmlTitle { get; set; }
}

public abstract class Http
{
    public Request Request { get; set; }
    public Response Response { get; set; }
}

public abstract class Software
{
    public string Vendor { get; set; }
    public string Product { get; set; }
    public string Version { get; set; }
}

public abstract class Vulnerability
{
    public string Id { get; set; }
    public string Cvss { get; set; }
    public string Type { get; set; }
    public string IsExploit { get; set; }
    public string Reference { get; set; }
}

public abstract class Service
{
    public Http Http { get; set; }
    public string Port { get; set; }
    public string ServiceName { get; set; }
    public List<string> Cpe { get; set; }
    public List<Software> Software { get; set; }
    public List<Vulnerability> Vulnerabilities { get; set; }
}

public abstract class Ssl
{
    public string Host { get; set; }
    public DateTime ExpiryDate { get; set; }
    public DateTime IssueDate { get; set; }
    public string Id { get; set; }
    public string Cipher { get; set; }
    public string Grade { get; set; }
    public string IssuerSubject { get; set; }
    public List<string> SubjectAltNames { get; set; }
    public string SubjectCn { get; set; }
    public string SerialNumber { get; set; }
    public string Raw { get; set; }
    public string SigAlg { get; set; }
    public string Subject { get; set; }
    public string ValidationType { get; set; }
    public string Version { get; set; }
}

public abstract class Subtech
{
    public string Technology { get; set; }
    public string Version { get; set; }
    public string Description { get; set; }
}

public abstract class Technology
{
    public string Categories { get; set; }
    public List<Subtech> Subtech { get; set; }
}

public abstract class AutonomousSystem
{
    public string AsNumber { get; set; }
    public string AsName { get; set; }
    public string AsCountry { get; set; }
    public List<string> AsRange { get; set; }
}

public abstract class OperatingSystem
{
    public string Vendor { get; set; }
    public List<string> Cpe { get; set; }
    public int Port { get; set; }
}

public abstract class Soa
{
    public string Name { get; set; }
    public string Ns { get; set; }
    public string Mailbox { get; set; }
    public int Serial { get; set; }
    public int Refresh { get; set; }
    public int Retry { get; set; }
    public int Expire { get; set; }
    public int Minttl { get; set; }
}

public abstract class Axfr
{
    public string Host { get; set; }
}

public abstract class Dns
{
    public int Ttl { get; set; }
    public List<string> Resolver { get; set; }
    public List<string> A { get; set; }
    public List<Soa> Soa { get; set; }
    public List<string> All { get; set; }
    public string StatusCode { get; set; }
    public Axfr Axfr { get; set; }
    public string Timestamp { get; set; }
}

public class ScanResult
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; }
    public string Domain { get; set; }
    public string DiscoveryReason { get; set; }
    public bool IsOnline { get; set; }
    public DateTime DiscoveryOn { get; set; }
    public List<string> Ip { get; set; }
    public List<Service> Services { get; set; }
    public Ssl Ssl { get; set; }
    public List<Technology> Technology { get; set; }
    public AutonomousSystem AutonomousSystem { get; set; }
    public OperatingSystem OperatingSystem { get; set; }
    public Dns Dns { get; set; }
}

public class ServerScanResult
{
    public string Status { get; set; }
    public ScanResult Results { get; set; }
}