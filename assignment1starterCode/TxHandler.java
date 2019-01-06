import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

public class TxHandler {

    private UTXOPool uPool;

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        this.uPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool, 
     * (2) the signatures on each input of {@code tx} are valid, 
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        ArrayList<Transaction.Input> inputs = tx.getInputs();
        ArrayList<Transaction.Output> outputs = tx.getOutputs();

        UTXOPool alreadySeenUTXOs = new UTXOPool();

        double sumOfOutputs = 0;
        for (Transaction.Output out : outputs)
        {
            // (4) all of {@code tx}s output values are non-negative
            if (out.value < 0) {
                System.out.println("ERROR: non-negative value found, returning false.");
                return false;
            }
            sumOfOutputs += out.value;
        }

        double sumOfInputs = 0;
        for (int i = 0; i < inputs.size(); i++) {
            Transaction.Input in = inputs.get(i);

            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);

            // (1) all outputs claimed by {@code tx} are in the current UTXO pool
            if (!this.uPool.contains(utxo)) {
                System.out.println("ERROR: output in tx is not found in current UTXO pool, returning false.");
                return false;
            }

            // (3) no UTXO is claimed multiple times by {@code tx}
            if (alreadySeenUTXOs.contains(utxo)) {
                System.out.println("ERROR: duplicate UTXO, returning false.");
                return false;
            }

            Transaction.Output output = this.uPool.getTxOutput(utxo);

            // (2) the signatures on each input of {@code tx} are valid
            PublicKey outPubKey = output.address;
            byte[] message = tx.getRawDataToSign(i);
            byte[] signature = in.signature;

            if (!Crypto.verifySignature(outPubKey, message, signature)) {
                System.out.println("ERROR: signature not verified, returning false.");
                return false;
            }

            // sum up output value
            sumOfInputs += output.value;

            // add each transaction to a unique pool so we can verify double spend
            alreadySeenUTXOs.addUTXO(utxo, output);
        }

        // (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
        //     *     values; and false otherwise.
        return sumOfInputs >= sumOfOutputs;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        List<Transaction> validatedTxs = new ArrayList<Transaction>();
        for (Transaction tx : possibleTxs) {
            // check to see if each possible transaction is valid
            if (isValidTx(tx)) {
                validatedTxs.add(tx);

                // update uPool

                // remove each transactions inputs from the uPool if they exist
                for (Transaction.Input in : tx.getInputs()) {
                    UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
                    this.uPool.removeUTXO(utxo);
                }

                for (int i = 0; i < tx.numOutputs(); i++) {
                    Transaction.Output out = tx.getOutput(i);
                    UTXO utxo = new UTXO(tx.getHash(), i);
                    this.uPool.addUTXO(utxo, out);
                }
            }
        }
        return validatedTxs.toArray(new Transaction[validatedTxs.size()]);
    }

}
