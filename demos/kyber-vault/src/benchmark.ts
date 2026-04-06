import { decapsulate, encapsulate, generateKeyPair, type MLKEMVariant } from './crypto/mlkem';

export interface VariantBenchmarkRow {
  variant: MLKEMVariant;
  keygenOpsPerSecond: number;
  encapsOpsPerSecond: number;
  decapsOpsPerSecond: number;
}

export interface BenchmarkReport {
  variants: VariantBenchmarkRow[];
  x25519OpsPerSecond: number | null;
}

type ProgressCallback = (message: string) => void;

const VARIANTS: MLKEMVariant[] = ['ml-kem-512', 'ml-kem-768', 'ml-kem-1024'];
const ITERATIONS = 100;

function now(): number {
  return performance.now();
}

async function yieldToUI(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

async function benchmarkLoop(
  label: string,
  iterations: number,
  progress: ProgressCallback,
  task: (iteration: number) => Promise<void>,
): Promise<number> {
  const start = now();
  for (let i = 0; i < iterations; i += 1) {
    await task(i);
    if ((i + 1) % 10 === 0) {
      progress(`${label}: ${i + 1}/${iterations}`);
      await yieldToUI();
    }
  }
  const elapsedSeconds = (now() - start) / 1000;
  return iterations / elapsedSeconds;
}

async function benchmarkX25519(progress: ProgressCallback): Promise<number | null> {
  if (!crypto.subtle) {
    return null;
  }
  try {
    const ops = await benchmarkLoop('X25519 ECDH', ITERATIONS, progress, async () => {
      const alice = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
      const bob = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
      await crypto.subtle.deriveBits(
        {
          name: 'X25519',
          public: bob.publicKey,
        },
        alice.privateKey,
        256,
      );
    });
    return ops;
  } catch {
    return null;
  }
}

export async function runBenchmark(progress: ProgressCallback): Promise<BenchmarkReport> {
  const rows: VariantBenchmarkRow[] = [];

  for (const variant of VARIANTS) {
    progress(`Preparing ${variant} benchmark...`);
    const stableKeyPair = await generateKeyPair(variant);

    const keygenOps = await benchmarkLoop(`${variant} keygen`, ITERATIONS, progress, async () => {
      await generateKeyPair(variant);
    });

    const encapsOps = await benchmarkLoop(`${variant} encaps`, ITERATIONS, progress, async () => {
      await encapsulate(stableKeyPair.publicKey, variant);
    });

    const decapsData: { ciphertext: Uint8Array; privateKey: Uint8Array }[] = [];
    for (let i = 0; i < ITERATIONS; i += 1) {
      const kp = await generateKeyPair(variant);
      const enc = await encapsulate(kp.publicKey, variant);
      decapsData.push({ ciphertext: enc.ciphertext, privateKey: kp.privateKey });
      if ((i + 1) % 20 === 0) {
        await yieldToUI();
      }
    }

    const decapsOps = await benchmarkLoop(`${variant} decaps`, ITERATIONS, progress, async (i) => {
      const item = decapsData[i];
      await decapsulate(item.ciphertext, item.privateKey, variant);
    });

    rows.push({
      variant,
      keygenOpsPerSecond: keygenOps,
      encapsOpsPerSecond: encapsOps,
      decapsOpsPerSecond: decapsOps,
    });
  }

  progress('Running X25519 benchmark...');
  const x25519OpsPerSecond = await benchmarkX25519(progress);
  progress('Benchmark complete');

  return {
    variants: rows,
    x25519OpsPerSecond,
  };
}
