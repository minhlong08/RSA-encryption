import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import importlib

# Import RSA modules
import rsa
import rsa_simple
import breaking_rsa

KEYGEN_ALGOS = {
    "RSA": lambda bits: rsa.RSA(bits).generate_keypair(),
    "RSA_simple": lambda bits: rsa_simple.RSA_SIMPLE().generate_keys()
}


BREAKING_ALGOS = {
    "naive": breaking_rsa.BREAKING_RSA.trial_division,
    "fermat": breaking_rsa.BREAKING_RSA.fermat_factor,
    "pollard_rho": breaking_rsa.BREAKING_RSA.pollards_rho
}

BREAK_TIMEOUT = 300  # seconds
stop_breaking = False


class RSAGUI:
    def __init__(self, root):
        self.root = root
        root.title("RSA Encryption GUI")
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill="both")

        self.build_keygen_tab()
        self.build_encrypt_tab()
        self.build_decrypt_tab()
        self.build_break_tab()

    def build_keygen_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Key Generation")

        ttk.Label(tab, text="Key Length (bits):").pack()
        self.key_length = tk.IntVar(value=256)
        ttk.Entry(tab, textvariable=self.key_length).pack()

        ttk.Label(tab, text="Algorithm:").pack()
        self.keygen_algo = tk.StringVar(value="RSA")
        ttk.OptionMenu(tab, self.keygen_algo, "RSA", *KEYGEN_ALGOS.keys()).pack()

        ttk.Button(tab, text="Generate Keys", command=self.generate_keys).pack(pady=5)
        self.key_output = scrolledtext.ScrolledText(tab, height=5)
        self.key_output.pack()

    def build_encrypt_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Encrypt")

        ttk.Label(tab, text="Public Key (e,n):").pack()
        self.encrypt_key = tk.StringVar()
        ttk.Entry(tab, textvariable=self.encrypt_key).pack()

        ttk.Label(tab, text="Message:").pack()
        self.encrypt_msg = tk.StringVar()
        ttk.Entry(tab, textvariable=self.encrypt_msg).pack()

        ttk.Button(tab, text="Encrypt", command=self.encrypt_message).pack(pady=5)
        self.encrypt_output = scrolledtext.ScrolledText(tab, height=5)
        self.encrypt_output.pack()

    def build_decrypt_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Decrypt")

        ttk.Label(tab, text="Private Key (d,n):").pack()
        self.decrypt_key = tk.StringVar()
        ttk.Entry(tab, textvariable=self.decrypt_key).pack()

        ttk.Label(tab, text="Encrypted Blocks (space-separated):").pack()
        self.decrypt_msg = tk.StringVar()
        ttk.Entry(tab, textvariable=self.decrypt_msg).pack()

        ttk.Button(tab, text="Decrypt", command=self.decrypt_message).pack(pady=5)
        self.decrypt_output = scrolledtext.ScrolledText(tab, height=5)
        self.decrypt_output.pack()

    def build_break_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Break RSA")

        ttk.Label(tab, text="Public Key (e,n):").pack()
        self.break_key = tk.StringVar()
        ttk.Entry(tab, textvariable=self.break_key).pack()

        ttk.Label(tab, text="Algorithm:").pack()
        self.break_algo = tk.StringVar(value="naive")
        ttk.OptionMenu(tab, self.break_algo, "naive", *BREAKING_ALGOS.keys()).pack()

        ttk.Button(tab, text="Break Key", command=self.break_key_threaded).pack(pady=5)
        ttk.Button(tab, text="Stop Breaking", command=self.stop_breaking_rsa).pack(pady=5)
        self.break_output = scrolledtext.ScrolledText(tab, height=6)
        self.break_output.pack()

    def generate_keys(self):
        algo = self.keygen_algo.get()
        bits = self.key_length.get()
        try:
            public_key, private_key = KEYGEN_ALGOS[algo](bits)
            e, n = public_key
            d, _ = private_key
            self.key_output.delete("1.0", tk.END)
            self.key_output.insert(tk.END, f"Public Key (e,n): ({e}, {n})\n")
            self.key_output.insert(tk.END, f"Private Key (d,n): ({d}, {n})")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def encrypt_message(self):
        try:
            e_str, n_str = self.encrypt_key.get().split(",")
            e, n = int(e_str.strip()), int(n_str.strip())
            msg = self.encrypt_msg.get()

            rsa_instance = rsa.RSA()
            rsa_instance.public_key = (e, n)
            blocks = rsa_instance.encrypt_string(msg, (e, n))

            self.encrypt_output.delete("1.0", tk.END)
            self.encrypt_output.insert(tk.END, " ".join(map(str, blocks)))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_message(self):
        try:
            d_str, n_str = self.decrypt_key.get().split(",")
            d, n = int(d_str.strip()), int(n_str.strip())
            blocks = list(map(int, self.decrypt_msg.get().split()))

            rsa_instance = rsa.RSA()
            rsa_instance.private_key = (d, n)
            msg = rsa_instance.decrypt_string(blocks, (d, n))

            self.decrypt_output.delete("1.0", tk.END)
            self.decrypt_output.insert(tk.END, msg)
        except Exception as e:
            messagebox.showerror("Error", str(e))


    def break_key_threaded(self):
        thread = threading.Thread(target=self.break_key_action)
        thread.daemon = True
        thread.start()

    def stop_breaking_rsa(self):
        global stop_breaking
        stop_breaking = True

    def break_key_action(self):
        global stop_breaking
        stop_breaking = False
        try:
            e_str, n_str = self.break_key.get().split(",")
            e, n = int(e_str.strip()), int(n_str.strip())
            algo = self.break_algo.get()
            self.break_output.delete("1.0", tk.END)
            self.break_output.insert(tk.END, "Breaking started...\n")

            def timeout_handler():
                time.sleep(BREAK_TIMEOUT)
                if not stop_breaking:
                    stop_breaking = True

            threading.Thread(target=timeout_handler, daemon=True).start()
            start = time.time()
            d, _ = BREAKING_ALGOS[algo]((e, n))
            elapsed = time.time() - start

            if stop_breaking:
                self.break_output.insert(tk.END, "Stopped or timed out.\n")
            else:
                self.break_output.insert(tk.END, f"Private Key (d,n): ({d}, {n})\nTime taken: {elapsed:.2f}s")
        except Exception as e:
            self.break_output.insert(tk.END, f"Error: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    RSAGUI(root)
    root.mainloop()
