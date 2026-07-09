import { Paybond } from "@paybond/kit";

declare const process: {
  env: Record<string, string | undefined>;
};

export async function createPaybondClient(): Promise<Paybond> {
  const apiKey = process.env.PAYBOND_API_KEY?.trim();
  if (!apiKey) {
    throw new Error("PAYBOND_API_KEY is required; run paybond login");
  }
  return Paybond.open({
    apiKey,
    gatewayBaseUrl: process.env.PAYBOND_GATEWAY_URL ?? process.env.PAYBOND_GATEWAY_BASE_URL,
    expectedEnvironment: "sandbox",
  });
}
