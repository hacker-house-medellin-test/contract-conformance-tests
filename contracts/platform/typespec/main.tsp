// Independently authored TypeSpec peer authority. Generated JSON Schema is comparison evidence only.
import "@typespec/json-schema";
using TypeSpec.JsonSchema;

namespace HackerHouseMedellin.Platform;

@id("ReservationContract")
model ReservationContract {
  repository: string;
  enabled: boolean;
  owner?: string;
}
