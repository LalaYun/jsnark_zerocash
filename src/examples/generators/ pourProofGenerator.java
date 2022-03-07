package src.examples.generators;

import java.math.BigInteger;

import util.Util;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.hash.meMerkleTreePathGadget;
import examples.gadgets.hash.*;



public class pourProofGenerator extends CircuitGenerator {

    /* For the real rt, coin_old, coin_new */
    private Wire[] rt;
    private Wire[] intermediateHasheWires;
    private Wire directionSelector;

    private int leafNumOfWords = 10;
    private int leafWordBitWidth = 32;
    private int treeHeight;

    private Wire[] cm_Old;
    private Wire[] addrPk_Old;
    private Wire[] addrSk_Old;
    private Wire Rho_Old;
    private Wire Value_Old;
    private Wire[] sn_Old;

    private Wire[] cm_New;
    private Wire[] addrPk_New;
    private Wire[] addrSk_New;
    private Wire Rho_New;
    private Wire Value_New;
    private Wire[] sn_New;

    /* For the computed coin_old, coin_new */
    private Wire[] compute_cm_Old;
    private Wire[] compute_addrPk_Old;
    private Wire[] compute_addrSk_Old;
    private Wire compute_Rho_Old;
    private Wire compute_Value_Old;
    private Wire[] compute_sn_Old;

    private Wire[] compute_cm_New;
    private Wire[] compute_addrPk_New;
    private Wire[] compute_addrSk_New;
    private Wire compute_Rho_New;
    private Wire compute_Value_New;
    private Wire[] compute_sn_New;
    
    /* For the proof */
    private int hashDigestDimension = 8;

    

    private meMerkleTreePathGadget merkleTreeGadget;
    private coin coin1;
    private coin coin2;
    
    public pourProofGenerator(String circuitName, int treeHeight) {
        super(circuitName);
        this.treeHeight = treeHeight;
    }



    @Override
    protected void buildCircuit() {

        /* argument : Wire[] addrPk, Wire value, Wire rho */
        
        coin1 = new coin(addrPk_Old, Value_Old, Rho_Old);
        Wire[] coin_old = coin1.getOutputWires();

        coin2 = new coin(addrPk_New, Value_New, Rho_New);
        Wire[] coin_new = coin2.getOutputWires();

        for (int i = 0; i < 8; i++){ cm_Old[i] = coin_old[i + 12]; }
        for (int i = 0; i < 8; i++){ cm_New[i] = coin_new[i + 12]; }
        


        // ====================================================================================
        // =============== (a) does cm_old's root is same as Merkle Tree root ? =============== 

        merkleTreeGadget = new meMerkleTreePathGadget(
                directionSelector, cm_Old, intermediateHasheWires, leafWordBitWidth, treeHeight);

        /** declare inputs **/
        rt = createInputWireArray(hashDigestDimension, "old coin's Root");
        intermediateHasheWires = createProverWitnessWireArray(hashDigestDimension * treeHeight, "Intermediate Hashes");
        directionSelector = createProverWitnessWire("Direction selector");
        cm_Old = createProverWitnessWireArray(leafNumOfWords, "Commitment");

        /** connect gadget **/
        merkleTreeGadget = new meMerkleTreePathGadget(
                directionSelector, cm_Old, intermediateHasheWires, leafWordBitWidth, treeHeight);
        Wire[] actualRoot = merkleTreeGadget.getOutputWires();
        
        /** Now compare the actual root with the public known root **/
        Wire errorAccumulator = getZeroWire();
        for(int i = 0; i < hashDigestDimension; i++){
            Wire diff = actualRoot[i].sub(rt[i]);
            Wire check = diff.checkNonZero();
            errorAccumulator = errorAccumulator.add(check);
        }
        makeOutputArray(actualRoot, "Computed Root");
        
        /** Expected mismatch here if the sample input below is tried **/
        makeOutput(errorAccumulator.checkNonZero(), "Error if NON-zero");
            

        for (int i = 0; i < 8; i++) {
            addEqualityAssertion(actualRoot[i], rt[i]);
        }

        /** If the proof(a) is correct **/
        printState("Proof A is correct");


        
        // ====================================================================================
        // ============ (b) does addrPk_old match the value of 'hash(addrSk_old)'? ============ 

        // declare addrSk_Old
        addrSk_Old = createProverWitnessWireArray(1);
        addrPk_Old = new SHA256Gadget(addrSk_Old, 32, 4, false, true).getOutputWires();
        
        for (int i = 0; i < 8; i++){
            addEqualityAssertion(addrPk_Old[i], compute_addrPk_Old[i]);
        }

        /** If the proof(b) is correct  **/
        printState("Proof B is correct");



        // ===========================================================================================
        // ============ (c) does sn_Old match the value of 'hash(addrSk_Old || Rho_Old)'? ============ 

        sn_Old = createProverWitnessWireArray(8);
        Wire[] beforeHash1 = new Wire[2]; // beforeHash = addrSk (1) || rho (1)
        beforeHash1[0] = addrSk_Old[0];
        beforeHash1[1] = Rho_Old;

        Wire[] intermediate1 = new WireArray(beforeHash1).getBits(64).asArray();
        sn_Old = new SHA256Gadget(intermediate1, 1, 8, false, true).getOutputWires(); // = hash(addrSk || rho)

        for (int i = 0; i < 8; i ++ ) {
            addEqualityAssertion(sn_Old[i], compute_sn_Old[i]);
        }

        /** If the proof(c) is correct **/
        printState("Proof C is correct");



        // =================================================================================================================
        // ============ (d) does cm_Old match the value of 'hash ( hash(addrPk_Old || Rho_Old) || Value_Old )'? ============ 

        for (int i = 0; i < 8; i ++ ) {
            addEqualityAssertion(cm_Old[i], compute_cm_Old[i]);
        }

        /** If the proof(d) is correct **/
        printState("Proof D is correct");



        // =================================================================================================================
        // ============ (e) does cm_New match the value of 'hash ( hash(addrPk_New || Rho_New) || Value_New )'? ============ 

        for (int i = 0; i < 8; i ++ ) {
            addEqualityAssertion(cm_New[i], compute_cm_New[i]);
        }

        /** If the proof(E) is correct, ProofTrue++ (5) **/
        printState("Proof E is correct");
    }

    @Override
    public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
        
        circuitEvaluator.setWireValue(rt[0], new BigInteger("1457221560"));
        circuitEvaluator.setWireValue(rt[1], new BigInteger("4173254931"));
        circuitEvaluator.setWireValue(rt[2], new BigInteger("2132407628"));
        circuitEvaluator.setWireValue(rt[3], new BigInteger("383242656"));
        circuitEvaluator.setWireValue(rt[4], new BigInteger("428419032"));
        circuitEvaluator.setWireValue(rt[5], new BigInteger("3643543674"));
        circuitEvaluator.setWireValue(rt[6], new BigInteger("539206213"));
        circuitEvaluator.setWireValue(rt[7], new BigInteger("1925885033"));

        // for (int i = 0; i < hashDigestDimension; i++) {
        //  circuitEvaluator.setWireValue(publicRootWires[i], new BigInteger("1111111111"));
        // }
        
        circuitEvaluator.setWireValue(directionSelector, new BigInteger("0"));

        for (int i = 0; i < hashDigestDimension*treeHeight; i++) {
            circuitEvaluator.setWireValue(intermediateHasheWires[i], new BigInteger("1111111111"));
        }
        
        for(int i = 0; i < leafNumOfWords; i++){
            circuitEvaluator.setWireValue(cm_Old[i], Integer.MAX_VALUE);
        }
        
    }
    
    
    public static void main(String[] args) throws Exception {
        
        pourProofGenerator generator = new pourProofGenerator("< PourProof >", 2);
        generator.generateCircuit();
        generator.evalCircuit();
        generator.prepFiles();
        generator.runLibsnark();        
    }

    
}
