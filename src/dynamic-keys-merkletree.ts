import {
    DynamicProof,
    FeatureFlags,
    Field,
    MerkleTree,
    MerkleWitness,
    Proof,
    SelfProof,
    Struct,
    VerificationKey,
    ZkProgram,
    verify,
} from 'o1js';

/**
 * This example showcases how DynamicProofs can be used along with a merkletree that stores
 * the verification keys that can be used to verify it.
 * The MainProgram has two methods, addSideloadedProgram that adds a given verification key
 * to the tree, and validateUsingTree that uses a given tree leaf to verify a given child-proof
 * using the verification tree stored under that leaf.
 */

const sideloadedProgram = ZkProgram({
    name: 'childProgram',
    publicInput: Field,
    publicOutput: Field,
    methods: {
        compute: {
            privateInputs: [Field],
            async method(publicInput: Field, privateInput: Field) {
                return publicInput.add(privateInput);
            },
        },
        assertAndAdd: {
            privateInputs: [Field],
            async method(publicInput: Field, privateInput: Field) {
                // this uses assert to test range check gates and their feature flags
                publicInput.assertLessThanOrEqual(privateInput);
                return publicInput.add(privateInput);
            },
        },
    },
});

const sideloadedProgram2 = ZkProgram({
    name: 'childProgram2',
    publicInput: Field,
    publicOutput: Field,
    methods: {
        compute: {
            privateInputs: [Field],
            async method(publicInput: Field, privateInput: Field) {
                return publicInput.mul(privateInput);
            },
        },
        assertAndMul: {
            privateInputs: [Field],
            async method(publicInput: Field, privateInput: Field) {
                // this uses assert to test range check gates and their feature flags
                publicInput.assertLessThanOrEqual(privateInput);
                return publicInput.mul(privateInput);
            },
        },
    },
});


// given a zkProgram, we compute the feature flags that we need in order to verify proofs that were generated
const commonFeatureFlags = await FeatureFlags.fromZkProgramList([sideloadedProgram, sideloadedProgram2]);

class SideloadedProgramProof extends DynamicProof<Field, Field> {
    static publicInputType = Field;
    static publicOutputType = Field;
    static maxProofsVerified = 0 as const;

    // we use the feature flags that we computed from the `sideloadedProgram` ZkProgram
    static featureFlags = commonFeatureFlags;
}

const tree = new MerkleTree(64);
class MerkleTreeWitness extends MerkleWitness(64) { }

class MainProgramState extends Struct({
    treeRoot: Field,
    state: Field,
}) { }

const mainProgram = ZkProgram({
    name: 'mainProgram',
    publicInput: MainProgramState,
    publicOutput: MainProgramState,
    methods: {
        addSideloadedProgram: {
            privateInputs: [VerificationKey, MerkleTreeWitness],
            async method(
                publicInput: MainProgramState,
                vk: VerificationKey,
                merkleWitness: MerkleTreeWitness
            ) {
                // In practice, this method would be guarded via some access control mechanism
                const currentRoot = merkleWitness.calculateRoot(Field(0));
                publicInput.treeRoot.assertEquals(
                    currentRoot,
                    'Provided merklewitness not correct or leaf not empty'
                );
                const newRoot = merkleWitness.calculateRoot(vk.hash);

                return new MainProgramState({
                    state: publicInput.state,
                    treeRoot: newRoot,
                });
            },
        },
        validateUsingTree: {
            privateInputs: [
                SelfProof,
                VerificationKey,
                MerkleTreeWitness,
                SideloadedProgramProof,
            ],
            async method(
                publicInput: MainProgramState,
                previous: Proof<MainProgramState, MainProgramState>,
                vk: VerificationKey,
                merkleWitness: MerkleTreeWitness,
                proof: SideloadedProgramProof
            ) {
                // Verify previous program state
                previous.publicOutput.state.assertEquals(publicInput.state);
                previous.publicOutput.treeRoot.assertEquals(publicInput.treeRoot);

                // Verify inclusion of vk inside the tree
                const computedRoot = merkleWitness.calculateRoot(vk.hash);
                publicInput.treeRoot.assertEquals(
                    computedRoot,
                    'Tree witness with provided vk not correct'
                );

                proof.verify(vk);

                // Compute new state
                proof.publicInput.assertEquals(publicInput.state);
                const newState = proof.publicOutput;
                return new MainProgramState({
                    treeRoot: publicInput.treeRoot,
                    state: newState,
                });
            },
        },
    },
});

console.log('Compiling circuits...');
const programVk = (await sideloadedProgram.compile()).verificationKey;
const program2Vk = (await sideloadedProgram2.compile()).verificationKey;
const mainVk = (await mainProgram.compile()).verificationKey;

// adding the first program's vk to the tree
console.log('Proving deployment of side-loaded key');
const rootBefore = tree.getRoot();
tree.setLeaf(1n, programVk.hash);
let witness = new MerkleTreeWitness(tree.getWitness(1n));

const proof1 = await mainProgram.addSideloadedProgram(
    new MainProgramState({
        treeRoot: rootBefore,
        state: Field(0),
    }),
    programVk,
    witness
);

// adding the second program's vk to the tree
console.log('Proving deployment of side-loaded key2');
const rootBefore2 = tree.getRoot();
tree.setLeaf(2n, program2Vk.hash);
const witness2 = new MerkleTreeWitness(tree.getWitness(2n));

// Recalculate the first witness for the new root
witness = new MerkleTreeWitness(tree.getWitness(1n));

const proof2 = await mainProgram.addSideloadedProgram(
    new MainProgramState({
        treeRoot: rootBefore2,
        state: Field(0),
    }),
    program2Vk,
    witness2
);

// calculate the proof for the first program's compute
console.log('Proving child program execution');
const childProof = await sideloadedProgram.compute(Field(0), Field(10));

console.log('Proving verification inside main program');
const proof3 = await mainProgram.validateUsingTree(
    proof2.publicOutput,
    proof2,
    programVk,
    witness,
    SideloadedProgramProof.fromProof(childProof)
);

const validProof2 = await verify(proof3, mainVk);
console.log('ok?', validProof2);

console.log('Proving different method of child program');
const childProof2 = await sideloadedProgram.assertAndAdd(Field(10), Field(12));

console.log('Proving verification inside main program');
const proof4 = await mainProgram.validateUsingTree(
    proof3.publicOutput,
    proof3,
    programVk,
    witness,
    SideloadedProgramProof.fromProof(childProof2)
);

const validProof4 = await verify(proof4, mainVk);
console.log('ok?', validProof4)

console.log('Proving method of child program 2');
const childProof3 = await sideloadedProgram2.compute(Field(22), Field(8));

console.log('Providing verification inside main program');
const proof5 = await mainProgram.validateUsingTree(
    proof4.publicOutput,
    proof4,
    program2Vk,
    witness2,
    SideloadedProgramProof.fromProof(childProof3)
);

const validProof5 = await verify(proof5, mainVk);
console.log('ok?', validProof5);

console.log('Prooving different method of child program 2');
const childProof4 = await sideloadedProgram2.assertAndMul(Field(176), Field(200));

console.log('Providing verification inside main program');
const proof6 = await mainProgram.validateUsingTree(
    proof5.publicOutput,
    proof5,
    program2Vk,
    witness2,
    SideloadedProgramProof.fromProof(childProof4)
);

const validProof6 = await verify(proof6, mainVk);
console.log('ok?', validProof6);