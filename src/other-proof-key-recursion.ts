import {
    ZkProgram,
    Field,
    DynamicProof,
    Proof,
    VerificationKey,
    Undefined,
    verify,
    Poseidon,
    Provable,
} from 'o1js';

class DynamicMultiplyProof extends DynamicProof<Undefined, Field> {
    static publicInputType = Undefined;
    static publicOutputType = Field;
    static maxProofsVerified = 0 as const;
}

// calculated from a previous run
const trustedMulVkHash = Field.fromValue(8142940553167082449842668986851829272657527115204486450531957647731361130797n);

const add = ZkProgram({
    name: 'add',
    publicInput: Undefined,
    publicOutput: Field,
    methods: {
        performAddition: {
            privateInputs: [Field, DynamicMultiplyProof, VerificationKey],
            async method(
                field: Field,
                proof: DynamicMultiplyProof,
                vk: VerificationKey
            ) {
                // TODO The incoming verification key isn't constrained in any way, therefore a malicious prover
                // can inject any vk they like which could lead to security issues. In practice, there would always
                // be some sort of access control to limit the set of possible vks used.
                const vkFields = VerificationKey.toFields(vk);
                const vkHash = Poseidon.hash(vkFields);
                vkHash.assertEquals(trustedMulVkHash);

                const multiplyResult = proof.publicOutput;
                // Skip verification in case the input is 0 as that is our base-case
                proof.verifyIf(vk, multiplyResult.equals(Field(0)).not());

                const additionResult = multiplyResult.add(field);
                return additionResult;
            },
        },
    },
});

const multiply = ZkProgram({
    name: 'multiply',
    publicInput: Undefined,
    publicOutput: Field,
    methods: {
        performMultiplication: {
            privateInputs: [Field, Field],
            async method(field1: Field, field2: Field){
                const multiplicationResult = field1.mul(field2);
                return multiplicationResult;
            },
        },
    },
});

console.log('compiling circuits...');
const addVk = (await add.compile()).verificationKey;
const mulVk = (await multiply.compile()).verificationKey;

const mulVkFields = VerificationKey.toFields(mulVk);
const mulVkHash = Poseidon.hash(mulVkFields);
console.log('mulVkFields', mulVkFields.toString())
console.log('mulVk', mulVk.hash);
console.log('mulVkHash:', mulVkHash);

console.log('Proving base-case');
const dummyProof = await DynamicMultiplyProof.dummy(undefined, Field(0), 0);
const baseCase = await add.performAddition(Field(5), dummyProof, mulVk);

const validBaseCase = await verify(baseCase, addVk);
console.log('ok?', validBaseCase);

console.log('Proving first multiplication');
const multiply1 = await multiply.performMultiplication(Field(3), Field(3));

const validMultiplication = await verify(multiply1, mulVk);
console.log('ok?', validMultiplication);

console.log('Proving second (recursive) addition');
const add2 = await add.performAddition(
    Field(4),
    DynamicMultiplyProof.fromProof(multiply1),
    mulVk
);

const validAddition = await verify(add2, addVk);
console.log('ok?', validAddition);

console.log('Result (should be 13):', add2.publicOutput.toBigInt());