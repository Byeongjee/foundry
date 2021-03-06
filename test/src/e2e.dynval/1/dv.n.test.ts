// Copyright 2019 Kodebox, Inc.
// This file is part of CodeChain.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

import { expect } from "chai";
import RPC from "foundry-rpc";
import "mocha";
import * as stake from "../../stakeholder";

import { validators } from "../../../tendermint.dynval/constants";
import { faucetAddress, faucetSecret } from "../../helper/constants";
import { PromiseExpect } from "../../helper/promise";
import { findNode, setTermTestTimeout, withNodes } from "../setup";
import { H256 } from "../../primitives/src";

describe("Dynamic Validator N -> N", function() {
    const promiseExpect = new PromiseExpect();

    async function expectPossibleAuthors(
        rpc: RPC,
        expectedValidators: typeof validators,
        blockNumber?: number
    ) {
        const possibleAuthors = (await stake.getPossibleAuthors(
            rpc,
            blockNumber
        ))!;
        expect(possibleAuthors).to.have.lengthOf(expectedValidators.length);
        expect(possibleAuthors.map(x => x.value)).contains.all.members(
            expectedValidators.map(x => x.address.value)
        );
    }

    describe("1. No delegation, nominate, revoke, jail", async function() {
        const initialValidators = validators.slice(0, 3);
        const { nodes } = withNodes(this, {
            promiseExpect,
            overrideParams: {
                maxNumOfValidators: 3
            },
            validators: initialValidators.map((signer, index) => ({
                signer,
                delegation: 5000,
                deposit: 10_000_000 - index // tie-breaker
            }))
        });

        beforeEach(async function() {
            await expectPossibleAuthors(nodes[0].rpc, initialValidators);
        });

        it("should keep possible authors after a term change", async function() {
            const termWaiter = setTermTestTimeout(this, {
                terms: 1
            });

            await termWaiter.waitNodeUntilTerm(nodes[0], {
                target: 2,
                termPeriods: 1
            });
            const blockNumber = await nodes[0].rpc.chain.getBestBlockNumber();
            const termMetadata = await stake.getTermMetadata(
                nodes[0].rpc,
                blockNumber
            );
            expect(termMetadata).not.to.be.null;
            expect(termMetadata!.currentTermId).to.be.equals(2);
            expect(termMetadata!.lastTermFinishedBlockNumber).to.be.lte(
                blockNumber
            );

            await expectPossibleAuthors(
                nodes[0].rpc,
                initialValidators,
                blockNumber
            );
        });
    });

    describe("2. Delegate to the candidates but the total delegation is still less than the minimum delegation (Capped by maxNumOfValidators)", async function() {
        const { nodes } = withNodes(this, {
            promiseExpect,
            overrideParams: {
                maxNumOfValidators: 3,
                delegationThreshold: 1000
            },
            validators: [
                // Validators
                { signer: validators[0], delegation: 5000, deposit: 100000 },
                { signer: validators[1], delegation: 4900, deposit: 100000 },
                { signer: validators[2], delegation: 4800, deposit: 100000 },
                // Candidates
                { signer: validators[3], delegation: 4700, deposit: 100000 } // alice
            ]
        });
        const initialValidators = validators.slice(0, 3);
        const alice = validators[3];

        beforeEach(async function() {
            await expectPossibleAuthors(nodes[0].rpc, initialValidators);
        });

        it("should keep possible authors after a term change", async function() {
            const termWaiter = setTermTestTimeout(this, {
                terms: 1
            });

            const insufficientDelegationTx = await nodes[0].rpc.mempool.sendSignedTransaction(
                {
                    tx: nodes[0].testFramework.core
                        .createDelegateCCSTransaction({
                            delegatee: alice.address,
                            quantity: 50
                        })
                        .sign({
                            secret: faucetSecret,
                            seq: (await nodes[0].rpc.chain.getSeq({
                                address: faucetAddress.toString()
                            }))!,
                            fee: 10
                        })
                        .rlpBytes()
                        .toString("hex")
                }
            );
            await nodes[0].waitForTx(new H256(insufficientDelegationTx));

            await termWaiter.waitNodeUntilTerm(nodes[0], {
                target: 2,
                termPeriods: 1
            });
            const blockNumber = await nodes[0].rpc.chain.getBestBlockNumber();
            const termMetadata = await stake.getTermMetadata(
                nodes[0].rpc,
                blockNumber
            );
            expect(termMetadata).not.to.be.null;
            expect(termMetadata!.currentTermId).to.be.equals(2);
            expect(termMetadata!.lastTermFinishedBlockNumber).to.be.lte(
                blockNumber
            );
            await expectPossibleAuthors(
                nodes[0].rpc,
                initialValidators,
                blockNumber
            );
        });
    });

    describe("2. Delegate to the candidates but the total delegation is still less than the minimum delegation (Capped by delegationThreshold)", async function() {
        const { nodes } = withNodes(this, {
            promiseExpect,
            overrideParams: {
                maxNumOfValidators: 4,
                delegationThreshold: 1000
            },
            validators: [
                // Validators
                { signer: validators[0], delegation: 5000, deposit: 100000 },
                { signer: validators[1], delegation: 4900, deposit: 100000 },
                { signer: validators[2], delegation: 4800, deposit: 100000 },
                // Remain as candidates (Below delegationThreshold)
                { signer: validators[3], delegation: 900, deposit: 100000 } // alice
            ]
        });
        const initialValidators = validators.slice(0, 3);
        const alice = validators[3];

        beforeEach(async function() {
            await expectPossibleAuthors(nodes[0].rpc, initialValidators);
        });

        it("should keep possible authors after a term change", async function() {
            const termWaiter = setTermTestTimeout(this, {
                terms: 1
            });

            const insufficientDelegationTx = await nodes[0].rpc.mempool.sendSignedTransaction(
                {
                    tx: nodes[0].testFramework.core
                        .createDelegateCCSTransaction({
                            delegatee: alice.address,
                            quantity: 50
                        })
                        .sign({
                            secret: faucetSecret,
                            seq: (await nodes[0].rpc.chain.getSeq({
                                address: faucetAddress.toString()
                            }))!,
                            fee: 10
                        })
                        .rlpBytes()
                        .toString("hex")
                }
            );
            await nodes[0].waitForTx(new H256(insufficientDelegationTx));

            await termWaiter.waitNodeUntilTerm(nodes[0], {
                target: 2,
                termPeriods: 1
            });
            const blockNumber = await nodes[0].rpc.chain.getBestBlockNumber();
            const termMetadata = await stake.getTermMetadata(
                nodes[0].rpc,
                blockNumber
            );
            expect(termMetadata).not.to.be.null;
            expect(termMetadata!.currentTermId).to.be.equals(2);
            expect(termMetadata!.lastTermFinishedBlockNumber).to.be.lte(
                blockNumber
            );
            await expectPossibleAuthors(
                nodes[0].rpc,
                initialValidators,
                blockNumber
            );
        });
    });

    describe("3. Revoke the delegations of validator but it still delegated more than the minimum delegation (Capped by maxNumOfValidators)", async function() {
        const { nodes } = withNodes(this, {
            promiseExpect,
            overrideParams: {
                maxNumOfValidators: 3,
                delegationThreshold: 1000
            },
            validators: [
                // Validators
                { signer: validators[0], delegation: 5000, deposit: 100000 },
                { signer: validators[1], delegation: 4900, deposit: 100000 },
                { signer: validators[2], delegation: 4800, deposit: 100000 }, // Alice
                // Candidates
                { signer: validators[3], delegation: 4700, deposit: 100000 }
            ]
        });
        const initialValidators = validators.slice(0, 3);
        const alice = validators[2];

        beforeEach(async function() {
            await expectPossibleAuthors(nodes[0].rpc, initialValidators);
        });

        it("should keep possible authors after a term change", async function() {
            const termWaiter = setTermTestTimeout(this, {
                terms: 1
            });

            const insufficientDelegationTx = await nodes[0].rpc.mempool.sendSignedTransaction(
                {
                    tx: nodes[0].testFramework.core
                        .createRevokeTransaction({
                            delegatee: alice.address,
                            quantity: 50
                        })
                        .sign({
                            secret: faucetSecret,
                            seq: (await nodes[0].rpc.chain.getSeq({
                                address: faucetAddress.toString()
                            }))!,
                            fee: 10
                        })
                        .rlpBytes()
                        .toString("hex")
                }
            );
            await nodes[0].waitForTx(new H256(insufficientDelegationTx));

            await termWaiter.waitNodeUntilTerm(nodes[0], {
                target: 2,
                termPeriods: 1
            });
            const blockNumber = await nodes[0].rpc.chain.getBestBlockNumber();
            const termMetadata = await stake.getTermMetadata(
                nodes[0].rpc,
                blockNumber
            );
            expect(termMetadata).not.to.be.null;
            expect(termMetadata!.currentTermId).to.be.equals(2);
            expect(termMetadata!.lastTermFinishedBlockNumber).to.be.lte(
                blockNumber
            );
            await expectPossibleAuthors(
                nodes[0].rpc,
                initialValidators,
                blockNumber
            );
        });
    });

    describe("3. Revoke the delegations of validator but it still delegated more than the minimum delegation (Capped by delegationThreshold)", async function() {
        const { nodes } = withNodes(this, {
            promiseExpect,
            overrideParams: {
                maxNumOfValidators: 4,
                delegationThreshold: 1000
            },
            validators: [
                // Validators
                { signer: validators[0], delegation: 5000, deposit: 100000 },
                { signer: validators[1], delegation: 4900, deposit: 100000 },
                { signer: validators[2], delegation: 4800, deposit: 100000 }, // Alice
                // Remain as candidates (Below delegationThreshold)
                { signer: validators[3], delegation: 900, deposit: 100000 }
            ]
        });
        const initialValidators = validators.slice(0, 3);
        const alice = validators[2];

        beforeEach(async function() {
            await expectPossibleAuthors(nodes[0].rpc, initialValidators);
        });

        it("should keep possible authors after a term change", async function() {
            const termWaiter = setTermTestTimeout(this, {
                terms: 1
            });

            const insufficientDelegationTx = await nodes[0].rpc.mempool.sendSignedTransaction(
                {
                    tx: nodes[0].testFramework.core
                        .createRevokeTransaction({
                            delegatee: alice.address,
                            quantity: 50
                        })
                        .sign({
                            secret: faucetSecret,
                            seq: (await nodes[0].rpc.chain.getSeq({
                                address: faucetAddress.toString()
                            }))!,
                            fee: 10
                        })
                        .rlpBytes()
                        .toString("hex")
                }
            );
            await nodes[0].waitForTx(new H256(insufficientDelegationTx));

            await termWaiter.waitNodeUntilTerm(nodes[0], {
                target: 2,
                termPeriods: 1
            });
            const blockNumber = await nodes[0].rpc.chain.getBestBlockNumber();
            const termMetadata = await stake.getTermMetadata(
                nodes[0].rpc,
                blockNumber
            );
            expect(termMetadata).not.to.be.null;
            expect(termMetadata!.currentTermId).to.be.equals(2);
            expect(termMetadata!.lastTermFinishedBlockNumber).to.be.lte(
                blockNumber
            );
            await expectPossibleAuthors(
                nodes[0].rpc,
                initialValidators,
                blockNumber
            );
        });
    });

    describe("4. Nominate new candidate", async function() {
        const { nodes } = withNodes(this, {
            promiseExpect,
            overrideParams: {
                maxNumOfValidators: 5,
                delegationThreshold: 1000,
                minDeposit: 10000
            },
            validators: [
                // Validators
                { signer: validators[0], delegation: 5000, deposit: 100000 },
                { signer: validators[1], delegation: 4900, deposit: 100000 },
                { signer: validators[2], delegation: 4800, deposit: 100000 },
                // Eligibles
                { signer: validators[3] } // Alice
            ]
        });
        const initialValidators = validators.slice(0, 3);
        const alice = validators[3];

        beforeEach(async function() {
            await expectPossibleAuthors(nodes[0].rpc, initialValidators);
        });

        [
            {
                description: "with enough deposit, but without delegation",
                deposit: 100000,
                delegation: 0
            },
            {
                description:
                    "with enough deposit, but without enough delegation",
                deposit: 100000,
                delegation: 900
            },
            {
                description: "without enough deposit and delegation",
                deposit: 5000,
                delegation: 900
            },
            {
                description:
                    "without enough deposit, but with enough delegation",
                deposit: 5000,
                delegation: 5000
            }
        ].forEach(({ description, deposit, delegation }) => {
            describe(description, async function() {
                it("should keep possible authors after a term change", async function() {
                    const termWaiter = setTermTestTimeout(this, {
                        terms: 1
                    });
                    const aliceNode = findNode(nodes, alice);
                    const nominationTx = await aliceNode.rpc.mempool.sendSignedTransaction(
                        {
                            tx: aliceNode.testFramework.core
                                .createSelfNominateTransaction({
                                    deposit,
                                    metadata: ""
                                })
                                .sign({
                                    secret: alice.privateKey,
                                    seq: (await aliceNode.rpc.chain.getSeq({
                                        address: alice.address.toString()
                                    }))!,
                                    fee: 10
                                })
                                .rlpBytes()
                                .toString("hex")
                        }
                    );
                    await nodes[0].waitForTx(new H256(nominationTx));

                    if (delegation > 0) {
                        const tx = await nodes[0].rpc.mempool.sendSignedTransaction(
                            {
                                tx: nodes[0].testFramework.core
                                    .createDelegateCCSTransaction({
                                        delegatee: alice.address,
                                        quantity: delegation
                                    })
                                    .sign({
                                        secret: faucetSecret,
                                        seq: (await nodes[0].rpc.chain.getSeq({
                                            address: faucetAddress.toString()
                                        }))!,
                                        fee: 10
                                    })
                                    .rlpBytes()
                                    .toString("hex")
                            }
                        );
                        await nodes[0].waitForTx(new H256(tx));
                    }

                    await termWaiter.waitNodeUntilTerm(nodes[0], {
                        target: 2,
                        termPeriods: 1
                    });
                    const blockNumber = await nodes[0].rpc.chain.getBestBlockNumber();
                    const termMetadata = await stake.getTermMetadata(
                        nodes[0].rpc,
                        blockNumber
                    );
                    expect(termMetadata).not.to.be.null;
                    expect(termMetadata!.currentTermId).to.be.equals(2);
                    expect(termMetadata!.lastTermFinishedBlockNumber).to.be.lte(
                        blockNumber
                    );
                    await expectPossibleAuthors(
                        nodes[0].rpc,
                        initialValidators,
                        blockNumber
                    );
                });
            });
        });
    });

    afterEach(async function() {
        promiseExpect.checkFulfilled();
    });
});
