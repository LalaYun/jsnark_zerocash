/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package src.examples.generators;

import java.math.BigInteger;

import util.Util;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.hash.MerkleTreePathGadget;
import examples.gadgets.hash.SubsetSumHashGadget;


public class MerkleTreeMembershipCircuitGenerator extends CircuitGenerator {

	private Wire[] publicRootWires;
	private Wire[] intermediateHasheWires;
	private Wire directionSelector;
	private Wire[] leafWires;
	private int leafNumOfWords = 10;
	private int leafWordBitWidth = 32;
	private int treeHeight;
	private int hashDigestDimension = SubsetSumHashGadget.DIMENSION;

	private MerkleTreePathGadget merkleTreeGadget;
	
	public MerkleTreeMembershipCircuitGenerator(String circuitName, int treeHeight) {
		super(circuitName);
		this.treeHeight = treeHeight;
	}

	@Override
	protected void buildCircuit() {
		
		/** declare inputs **/
		
		publicRootWires = createInputWireArray(hashDigestDimension, "Input Merkle Tree Root");
		intermediateHasheWires = createProverWitnessWireArray(hashDigestDimension * treeHeight, "Intermediate Hashes");
		directionSelector = createProverWitnessWire("Direction selector"); //197 (nizkinput)
		leafWires = createProverWitnessWireArray(leafNumOfWords, "Secret Leaf");

		/** connect gadget **/

		merkleTreeGadget = new MerkleTreePathGadget(
				directionSelector, leafWires, intermediateHasheWires, leafWordBitWidth, treeHeight);
		Wire[] actualRoot = merkleTreeGadget.getOutputWires();
		
		/** Now compare the actual root with the public known root **/
		Wire errorAccumulator = getZeroWire();
		for(int i = 0; i < hashDigestDimension; i++){
			Wire diff = actualRoot[i].sub(publicRootWires[i]);
			Wire check = diff.checkNonZero();
			errorAccumulator = errorAccumulator.add(check);
		}
		
		makeOutputArray(actualRoot, "Computed Root");
		
		/** Expected mismatch here if the sample input below is tried**/
		makeOutput(errorAccumulator.checkNonZero(), "Error if NON-zero");
		
	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		
		circuitEvaluator.setWireValue(publicRootWires[0], new BigInteger("3381889868918180933877763128953114152270157455278978907439268280676460423426"));
		circuitEvaluator.setWireValue(publicRootWires[1], new BigInteger("17355687267797739276242994270053386604316383636425354773707690244515463261307"));
		circuitEvaluator.setWireValue(publicRootWires[2], new BigInteger("9745514306859303243432732012352867446789113915360877643336360729687606359748"));
		
		circuitEvaluator.setWireValue(directionSelector, new BigInteger("0"));

		for (int i = 0; i < hashDigestDimension*treeHeight; i++) {
			circuitEvaluator.setWireValue(intermediateHasheWires[i],  new BigInteger("11111111111111111111111111111111111111111111111111111111111111111111111111111"));
		}
		
		for(int i = 0; i < leafNumOfWords; i++){
			circuitEvaluator.setWireValue(leafWires[i], Integer.MAX_VALUE);
		}
		
	}
	
	
	public static void main(String[] args) throws Exception {
		
		MerkleTreeMembershipCircuitGenerator generator = new MerkleTreeMembershipCircuitGenerator("tree_2", 2);
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();		
	}

	
}
