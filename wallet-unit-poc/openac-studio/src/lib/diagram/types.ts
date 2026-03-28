export type DiagramLevel = "high_level" | "crypto_level";

export interface DiagramOutput {
  level: DiagramLevel;
  mermaid: string;
}
