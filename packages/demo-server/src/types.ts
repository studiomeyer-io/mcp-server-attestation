import { z } from "zod";

export const VerifyManifestArgs = z.object({
  manifestPath: z.string().min(1).max(4096),
  publicKeyPath: z.string().min(1).max(4096),
});
export type VerifyManifestArgs = z.infer<typeof VerifyManifestArgs>;

export const InspectSpawnArgs = z.object({
  command: z.string().min(1).max(512),
  args: z.array(z.string().max(8192)).max(64),
  manifest: z.record(z.string(), z.unknown()),
});
export type InspectSpawnArgs = z.infer<typeof InspectSpawnArgs>;

export const GenerateTemplateArgs = z.object({
  serverName: z.string().min(1).max(128),
  toolNames: z.array(z.string().min(1).max(128)).min(0).max(64),
});
export type GenerateTemplateArgs = z.infer<typeof GenerateTemplateArgs>;

export const SignManifestArgs = z.object({
  manifestPath: z.string().min(1).max(4096),
  privateKeyPath: z.string().min(1).max(4096),
  outputPath: z.string().min(1).max(4096),
});
export type SignManifestArgs = z.infer<typeof SignManifestArgs>;

export const KeygenArgs = z.object({
  outputDir: z.string().min(1).max(4096),
  keyName: z.string().min(1).max(128).regex(/^[a-zA-Z0-9._-]+$/),
});
export type KeygenArgs = z.infer<typeof KeygenArgs>;
