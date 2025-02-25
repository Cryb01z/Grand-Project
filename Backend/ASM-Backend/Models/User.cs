using MongoDB.Bson;

using MongoDB.Bson.Serialization.Attributes;

namespace ASM_Backend.Models;

public class User
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = ObjectId.GenerateNewId().ToString();
    public required string Name { get; set; }
    public required string Email { get; set; }
    public required string Password { get; set; }
    public required string[] Roles { get; set; }
}