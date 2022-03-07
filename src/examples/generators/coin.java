package src.examples.generators;

import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;

import examples.gadgets.hash.SHA256Gadget;

public class coin extends Gadget{
    
    public Wire[] addrPk; // hash, old = [], new = []
    private Wire value; // 2 digit, old = 1, new = 3
    private Wire rho; // 3 digit, old = 2, new = 4
    private Wire r; // 0
    private Wire s; // 0
    private Wire[] cm;
    // private Wire[] addrSk;

    private Wire[] Coin;

    // public coin_old(Wire[] addrPk_old, Wire[] random) {
    //     this.addrPk_old = addrPk_old;
    //     this.random = random; // 5678
    //     buildCircuit();
    // }

    public coin(Wire[] addrPk, Wire value, Wire rho, String... desc) {
        super(desc);
        this.addrPk = addrPk;
        this.value = value;
        this.rho = rho;
        buildCircuit();
    }
    
    private void buildCircuit() {
        
        /** Making CM **/
        Wire[] beforeHash1 = new Wire[9]; // beforeHash = addrPk[8] (8) || rho (1)
        for (int i=0; i<8; i++){ beforeHash1[i] = addrPk[i]; }
        beforeHash1[8] = rho;

        Wire[] intermediate1 = new WireArray(beforeHash1).getBits(288).asArray();
        Wire[] hashOut1 = new SHA256Gadget(intermediate1, 1, 36, false, true).getOutputWires(); // = hash(addrPk[0] || rho)

        Wire[] beforeHash2 = new Wire[9]; // beforeHash = hashOut (8) || value (1)
        for (int i=0; i<8; i++){ beforeHash2[i] = hashOut1[i]; }
        beforeHash2[8] = value;

        Wire[] intermediate2 = new WireArray(beforeHash2).getBits(288).asArray();
        cm = new SHA256Gadget(intermediate2, 1, 36, false, true).getOutputWires(); // = hash ( hash(addrPk || rho) || value )
    
        /** Appending addrPk (8), value (1), rho (1), r (1), s (1), CM (8) **/
        Coin = new Wire[20];
        for (int i=0; i<8; i++){ Coin[i] = addrPk[i]; }
        Coin[8] = value;
        Coin[9] = rho;
        Coin[10] = r;
        Coin[11] = s;
        for (int i = 0; i < 8 ; i++) { Coin[i + 12] = cm[i]; }

    }

    @Override
    public Wire[] getOutputWires() {

        return Coin;
    }
}
