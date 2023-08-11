import tkinter as tk
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import json
import os

class Transaction:
    def __init__(self, sender, recipient, amount, encrypted_transaction):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.encrypted_transaction = encrypted_transaction

    def to_dict(self):
        return {
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'encrypted_transaction': self.encrypted_transaction
        }

    def __str__(self):
        return f"From: {self.sender}, To: {self.recipient}, Amount: {self.amount}"

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.new_block(previous_hash='1')

    def new_block(self, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'transactions': self.current_transactions,
            'previous_hash': previous_hash,
        }
        self.current_transactions = []
        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount, encryption_key):
        encrypted_transaction = self.encrypt_transaction(sender, recipient, amount, encryption_key)
        self.current_transactions.append(Transaction(sender, recipient, amount, encrypted_transaction))
        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[-1]

    def encrypt_transaction(self, sender, recipient, amount, encryption_key):
        cipher_aes = AES.new(encryption_key, AES.MODE_EAX)
        nonce = cipher_aes.nonce
        data = json.dumps({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        }).encode()
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        encrypted_transaction = {
            'nonce': nonce.hex(),
            'ciphertext': ciphertext.hex(),
            'tag': tag.hex()
        }
        return encrypted_transaction

    def decrypt_transaction(self, encrypted_transaction, decryption_key):
        nonce = bytes.fromhex(encrypted_transaction['nonce'])
        ciphertext = bytes.fromhex(encrypted_transaction['ciphertext'])
        tag = bytes.fromhex(encrypted_transaction['tag'])
        cipher_aes = AES.new(decryption_key, AES.MODE_EAX, nonce=nonce)
        decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return json.loads(decrypted_data.decode())

class SecureCryptoWalletApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Crypto Wallet")
        self.root.configure(bg="#f3e6e1")  # Light coffee color
        
        self.label = tk.Label(root, text="Secure Crypto Wallet", font=("Helvetica", 16, "bold"), fg="blue", bg="#f3e6e1")
        self.label.pack(pady=20)
        
        self.frame_inputs = tk.Frame(root, bg="#f3e6e1")
        self.frame_inputs.pack()
        
        tk.Label(self.frame_inputs, text="Username:", bg="#f3e6e1").grid(row=0, column=0, padx=5, pady=5)
        tk.Label(self.frame_inputs, text="Password:", bg="#f3e6e1").grid(row=1, column=0, padx=5, pady=5)
        tk.Label(self.frame_inputs, text="Sender:", bg="#f3e6e1").grid(row=2, column=0, padx=5, pady=5)
        tk.Label(self.frame_inputs, text="Recipient:", bg="#f3e6e1").grid(row=3, column=0, padx=5, pady=5)
        tk.Label(self.frame_inputs, text="Amount:", bg="#f3e6e1").grid(row=4, column=0, padx=5, pady=5)

        self.username_entry = tk.Entry(self.frame_inputs)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        self.password_entry = tk.Entry(self.frame_inputs, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        self.sender_entry = tk.Entry(self.frame_inputs)
        self.sender_entry.grid(row=2, column=1, padx=5, pady=5)

        self.recipient_entry = tk.Entry(self.frame_inputs)
        self.recipient_entry.grid(row=3, column=1, padx=5, pady=5)

        self.amount_entry = tk.Entry(self.frame_inputs)
        self.amount_entry.grid(row=4, column=1, padx=5, pady=5)

        self.frame_buttons = tk.Frame(root, bg="#f3e6e1")
        self.frame_buttons.pack()
        
        self.create_button = tk.Button(self.frame_buttons, text="Create Transaction", command=self.create_transaction, bg="#d4a190", fg="black")
        self.create_button.grid(row=0, column=0, padx=5)
        
        self.mine_button = tk.Button(self.frame_buttons, text="Mine Block", command=self.mine_block, bg="orange", fg="white")
        self.mine_button.grid(row=0, column=1, padx=5)
        
        self.print_button = tk.Button(self.frame_buttons, text="Print Blockchain", command=self.print_blockchain, bg="purple", fg="white")
        self.print_button.grid(row=0, column=2, padx=5)
        
        self.exit_button = tk.Button(self.frame_buttons, text="Exit", command=self.root.quit, bg="red", fg="white")
        self.exit_button.grid(row=0, column=3, padx=5)
        
        self.result_text = tk.Text(root, height=10, width=40, bg="#f8f1f1")
        self.result_text.pack(pady=20)

        self.blockchain = Blockchain()
        self.encryption_key = get_random_bytes(16)

    def create_transaction(self):
        sender = self.username_entry.get()
        recipient = self.recipient_entry.get()
        amount = float(self.amount_entry.get())
        self.blockchain.new_transaction(sender, recipient, amount, self.encryption_key)
        self.result_text.insert(tk.END, "Transaction added to current block.\n")

        # Clear the input fields after creating a transaction
        self.username_entry.delete(0, tk.END)
        self.recipient_entry.delete(0, tk.END)
        self.amount_entry.delete(0, tk.END)

    def mine_block(self):
        last_block = self.blockchain.last_block
        previous_hash = hashlib.sha256(json.dumps(last_block, sort_keys=True).encode()).hexdigest()
        new_block = self.blockchain.new_block(previous_hash)
        self.result_text.insert(tk.END, f"Block mined!\nBlock Index: {new_block['index']}\nTransactions:\n")
        for tx in new_block['transactions']:
            self.result_text.insert(tk.END, str(tx) + "\n")

    def print_blockchain(self):
        blockchain_data = []
        for block in self.blockchain.chain:
            transactions = [tx.to_dict() for tx in block['transactions']]
            blockchain_data.append({
                'index': block['index'],
                'transactions': transactions,
                'previous_hash': block['previous_hash']
            })
        self.result_text.insert(tk.END, json.dumps(blockchain_data, indent=2) + "\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureCryptoWalletApp(root)
    root.mainloop()
