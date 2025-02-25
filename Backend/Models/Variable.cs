using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace ASM_Backend.Models;

public class Variable
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]    
    public string Id { get; set; } = ObjectId.GenerateNewId().ToString();
    public required string Name { get; set; }
    public required string Value { get; set; }
}