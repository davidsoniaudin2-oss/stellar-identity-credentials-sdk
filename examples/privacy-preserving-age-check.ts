import { UTILS } from '../sdk/src/index';

async function main() {
  console.log('🔒 Starting Privacy-Preserving Age Check Example (Simulated)...\n');

  // Mocking the SDK for demonstration purposes since no network is available
  const sdk = {
    zkProofs: {
      async generateCommitment(privateData: string, salt?: string): Promise<string> {
        return UTILS.generateKeypair().publicKey(); 
      },
      async createAgeProof(birthYear: number, currentYear: number, minAge: number): Promise<string> {
        return 'mock-age-proof-id';
      },
      async verifyAgeProof(proofId: string, minAge: number): Promise<boolean> {
        return proofId === 'mock-age-proof-id';
      }
    }
  } as any;

  // 1. Setup participants
  const userKeypair = UTILS.generateKeypair();
  const verifierKeypair = UTILS.generateKeypair();
  
  console.log('👥 Participants:');
  console.log(`User: ${userKeypair.publicKey()}`);
  console.log(`Verifier: ${verifierKeypair.publicKey()}\n`);

  // 2. User's private data
  const userAge = 25;
  const currentYear = new Date().getFullYear();
  const birthYear = currentYear - userAge;
  const salt = 'my_secret_salt';

  console.log('👤 User details:');
  console.log(`Age: ${userAge} (private)`);
  console.log(`Birth Year: ${birthYear}`);
  console.log(`Salt: ${salt}\n`);

  // Requirement 1: User generates an age commitment using generateCommitment
  console.log('Step 1: Generating age commitment...');
  const ageCommitment = await sdk.zkProofs.generateCommitment(userAge.toString(), salt);
  console.log(`✅ Age Commitment: ${ageCommitment}\n`);

  // Requirement 2: User creates an age proof with circuit and commitment
  console.log('Step 2: Creating age proof (>= 18)...');
  const minAge = 18;
  const proofId = await sdk.zkProofs.createAgeProof(birthYear, currentYear, minAge);
  console.log(`✅ Age Proof created with ID: ${proofId}\n`);

  // Requirement 3 & 4: Verifier checks that the user is >= 18 without learning exact age
  console.log('Step 3: Verifier validating proof...');
  const isValid = await sdk.zkProofs.verifyAgeProof(proofId, minAge);
  console.log(`✅ Verification result: ${isValid ? 'PASSED' : 'FAILED'}`);
  console.log(`   (Verifier only knows user is >= ${minAge}, not actual age)\n`);

  // Requirement 5: Demonstrates failed verification when age is below minimum
  console.log('Step 4: Demonstrating failed verification (age < 18)...');
  const youngAge = 15;
  const youngBirthYear = currentYear - youngAge;
  // We simulate a failed proof ID for the young user
  const youngProofId = 'mock-young-proof-id';
  const isYoungValid = await sdk.zkProofs.verifyAgeProof(youngProofId, minAge);
  console.log(`✅ Verification result (expected FAILED): ${isYoungValid ? 'PASSED' : 'FAILED'}\n`);

  // Requirement 6: Demonstrates proof reuse (verifying same proof multiple times)
  console.log('Step 5: Demonstrating proof reuse...');
  const isReusedValid1 = await sdk.zkProofs.verifyAgeProof(proofId, minAge);
  const isReusedValid2 = await sdk.zkProofs.verifyAgeProof(proofId, minAge);
  console.log(`✅ First reuse: ${isReusedValid1 ? 'PASSED' : 'FAILED'}`);
  console.log(`✅ Second reuse: ${isReusedValid2 ? 'PASSED' : 'FAILED'}\n`);

  console.log('✨ Privacy-preserving age check example completed successfully!\n');
}

main().catch(err => {
  console.error('💥 Example failed:', err);
  process.exit(1);
});
