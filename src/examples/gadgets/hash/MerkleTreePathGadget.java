/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.gadgets.hash;

import circuit.config.Config;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;


/**
 * A Merkle tree authentication gadget using the subsetsum hash function
 * 
 */

public class MerkleTreePathGadget extends Gadget {

	private static int digestWidth = SubsetSumHashGadget.DIMENSION;

	private int treeHeight;
	private Wire directionSelectorWire;
	private Wire[] directionSelectorBits;
	private Wire[] leafWires;
	private Wire[] intermediateHashWires;
	private Wire[] outRoot;

	private int leafWordBitWidth;

	public MerkleTreePathGadget(Wire directionSelectorWire, Wire[] leafWires, Wire[] intermediateHasheWires,
			int leafWordBitWidth, int treeHeight, String... desc) {

		super(desc);
		this.directionSelectorWire = directionSelectorWire;
		this.treeHeight = treeHeight;
		this.leafWires = leafWires;
		this.intermediateHashWires = intermediateHasheWires;
		this.leafWordBitWidth = leafWordBitWidth;

		buildCircuit();

	}

	private void buildCircuit() {

		directionSelectorBits = directionSelectorWire.getBitWires(treeHeight).asArray(); //direction selector의 역할 : 왼쪽 오른쪽에 대한 정보를 주어야 더한 값의 실제 위치를 알 수 있어서 ?

		// Apply CRH to leaf data
		Wire[] leafBits = new WireArray(leafWires).getBits(leafWordBitWidth).asArray();
		SubsetSumHashGadget subsetSumGadget = new SubsetSumHashGadget(leafBits, false); //false가 말하는 건 binaryOutput : Whether the output digest should be splitted into bits or not.
		Wire[] currentHash = subsetSumGadget.getOutputWires();

		// Apply CRH across tree path guided by the direction bits
		for (int i = 0; i < treeHeight; i++) {
			Wire[] inHash = new Wire[2 * digestWidth]; 
			//left ? 
			for (int j = 0; j < digestWidth; j++) {
				Wire temp = currentHash[j].sub(intermediateHashWires[i * digestWidth + j]);
				Wire temp2 = directionSelectorBits[i].mul(temp);
				inHash[j] = intermediateHashWires[i * digestWidth + j].add(temp2); // b + d(a-b)
			}
			//right ?
			for (int j = digestWidth; j < 2 * digestWidth; j++) {
				Wire temp = currentHash[j - digestWidth].add(intermediateHashWires[i * digestWidth + j - digestWidth]); // a+b
				inHash[j] = temp.sub(inHash[j - digestWidth]); // a+b - (b + d(a-b)) = a - d(a-b)
			}

			Wire[] nextInputBits = new WireArray(inHash).getBits(Config.LOG2_FIELD_PRIME).asArray();
			subsetSumGadget = new SubsetSumHashGadget(nextInputBits, false);
			currentHash = subsetSumGadget.getOutputWires();
		}
		outRoot = currentHash;
	}

	@Override
	public Wire[] getOutputWires() {
		return outRoot;
	}

}
