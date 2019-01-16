// deserialization
// @JsonDeserialize(using = MultiplicationResultAttemptDeserializer.class)
// add above annotation on model class level.

public class MultiplicationResultAttemptDeserializer extends JsonDeserializer<MultiplicationResultAttempt> {
              @Override
              public MultiplicationResultAttempt deserialize(JsonParser jsonParser, DeserializationContext deserializationContext)
              throws IOException, JsonProcessingException {
              
              
              ObjectCodec oc = jsonParser.getCodec();
              JsonNode node = oc.readTree(jsonParser);
              
              return new MultiplicationResultAttempt(node.
              get("user").get("alias").asText(),
              node.get("multiplication").get("factorA").asInt(),
              node.get("multiplication").get("factorB").asInt(),
              node.get("resultAttempt").asInt(),
              node.get("correct").asBoolean());
}
}


// extend this class as well. try this class
// JsonObjectDeserializer
