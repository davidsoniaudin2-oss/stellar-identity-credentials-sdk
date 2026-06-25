declare module 'snarkjs' {
  export const groth16: {
    fullProve: (
      inputs: any,
      wasm: any,
      zkey: any
    ) => Promise<{ proof: any; publicSignals: any }>;
  };
}
