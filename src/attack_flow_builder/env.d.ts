/// <reference types="vite/client" />

declare module "tie-inference-web" {
    export type TiePrediction = { id: string; score: number; rank: number };
    export type TieEngine = {
        warmup(): Promise<void>;
        predict(ids: Iterable<string>): Promise<TiePrediction[]>;
    };
    export function createEngine(
        npzUrl: string,
        enrichmentUrl?: string,
        cache?: boolean
    ): Promise<TieEngine>;
}
