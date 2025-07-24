from flask import Flask, render_template, request, jsonify
import threading
import time
import rsa
import rsa_simple
import rsa_pkcs
import rsa_oaep
import breaking_rsa

app = Flask(__name__)

KEYGEN_ALGOS = {
    "RSA": lambda bits: rsa.RSA(bits).generate_keypair(),
    "RSA_simple": lambda bits: rsa_simple.RSA_SIMPLE().generate_keys()
}

BREAKING_ALGOS = {
    "naive": breaking_rsa.BREAKING_RSA.trial_division_stoppable,
    "fermat": breaking_rsa.BREAKING_RSA.fermat_factor_stoppable,
    "pollard_rho": breaking_rsa.BREAKING_RSA.pollards_rho_stoppable
}

running_threads = {}
stop_events = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_key', methods=['POST'])
def generate_key():
    data = request.get_json()
    algo, bits = data['algo'], int(data['bits'])
    if algo not in KEYGEN_ALGOS:
        return jsonify({"error": "Invalid algorithm"})
    
    try:
        pub, priv = KEYGEN_ALGOS[algo](bits)
        public_key = {"e": str(pub[0]), "n": str(pub[1])}
        private_key = {"d": str(priv[0]), "n": str(priv[1])}
        return jsonify({"public": public_key, "private": private_key})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    e, n, text, algo = int(data['e']), int(data['n']), data['text'], data.get('algo', 'RSA')
    
    label = data.get('label', '')

    try:
        if algo == 'RSA':
            # Normal RSA with no padding
            rsa_instance = rsa.RSA()
            public_key = (e, n)
            encrypted_blocks = rsa_instance.encrypt_string(text, public_key)
            result = ' '.join(map(str, encrypted_blocks))
        elif algo == 'RSA(PKCS#1 v1.5)':
            rsa_pkcs_instance = rsa_pkcs.RSAWithPKCS1()
            public_key = (e, n)

            # check key length requirement
            if n.bit_length() < 96:
                return jsonify({"result": f"Key length too short, must be at least 96 bits"})
            
            encrypted_blocks = rsa_pkcs_instance.encrypt_string(text, public_key)
            result = ' '.join(map(str, encrypted_blocks))
        elif algo == 'RSA(OAEP)':
            rsa_oaep_instance = rsa_oaep.RSA_OAEP()
            public_key = (e, n)

            # check key length requirement
            if n.bit_length() < 536:
                return jsonify({"result": f"Key length too short, must be at least 536 bits"})
            
            label_bytes = label.encode('utf-8') if label else b''
            
            encrypted_blocks = rsa_oaep_instance.encrypt_string(text, public_key, label=label_bytes)
            result = ' '.join(map(str, encrypted_blocks))
        else:
            # Naive version of RSA (inefficient, byte to byte encrypting)
            rsa_simple_instance = rsa_simple.RSA_SIMPLE()
            public_key = (e, n)
            encrypted_blocks = rsa_simple_instance.encrypt(text, public_key)
            result = ' '.join(map(str, encrypted_blocks))
        
        return jsonify({"result": result})
    except Exception as ex:
        return jsonify({"result": f"Encryption failed: {str(ex)}"})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    d, n, text, algo = int(data['d']), int(data['n']), data['text'], data.get('algo', 'RSA')
    
    label = data.get('label', '')

    try:
        if algo == 'RSA':
            rsa_instance = rsa.RSA()
            private_key = (d, n)
            
            # Parse encrypted blocks
            encrypted_blocks = [int(block) for block in text.strip().split()]
            result = rsa_instance.decrypt_string(encrypted_blocks, private_key)
        elif algo == 'RSA(PKCS#1 v1.5)':
            rsa_pkcs_instance = rsa_pkcs.RSAWithPKCS1()
            private_key = (d,n)

            # Parse encrypted blocks
            encrypted_blocks = [int(block) for block in text.strip().split()]
            result = rsa_pkcs_instance.decrypt_string(encrypted_blocks, private_key)
        elif algo == 'RSA(OAEP)':
            rsa_oaep_instance = rsa_oaep.RSA_OAEP()
            private_key = (d, n)

            label_bytes = label.encode('utf-8') if label else b''

            # Parse encrypted blocks
            encrypted_blocks = [int(block) for block in text.strip().split()]
            result = rsa_oaep_instance.decrypt_string(encrypted_blocks, private_key, label=label_bytes)
        else:
            rsa_simple_instance = rsa_simple.RSA_SIMPLE()
            private_key = (d, n)
            
            # Parse encrypted blocks
            encrypted_blocks = [int(block) for block in text.strip().split()]
            result = rsa_simple_instance.decrypt(encrypted_blocks, private_key)
        
        return jsonify({"result": result})
    except ValueError as e:
        return jsonify({"result": f"Decryption failed: Invalid input - {str(e)}"})
    except Exception as e:
        return jsonify({"result": f"Decryption failed: {str(e)}"})

@app.route('/break_rsa', methods=['POST'])
def break_rsa():
    data = request.get_json()
    e, n, algo = int(data['e']), int(data['n']), data['algo']

    # Create a stop event for this breaking session
    stop_event = threading.Event()
    stop_events['breaker'] = stop_event
    
    result = {"result": ""}

    def target():
        try:
            start = time.time()
            
            public_key = (e, n)
            
            private_key_tuple = BREAKING_ALGOS[algo](public_key, stop_event)
            
            end = time.time()
            
            # Check if the process was stopped
            if stop_event.is_set():
                result["result"] = "Breaking process was stopped by user."
                return
            
            if private_key_tuple and private_key_tuple[0] is not None:
                # The breaking algorithms return (d, n) where d is the private key
                d, n_returned = private_key_tuple
                result["result"] = f"Successfully broke RSA key!\nPrivate key (d, n): ({d}, {n_returned})\nTime: {end - start:.9f} sec"
            else:
                result["result"] = "Failed to break key - no factors found."
                
        except Exception as ex:
            if stop_event.is_set():
                result["result"] = "Breaking process was stopped by user."
            else:
                result["result"] = "Error: " + str(ex)

    thread = threading.Thread(target=target)
    thread.start()
    running_threads['breaker'] = thread
    thread.join(timeout=86400)  # 1 day max run time

    if thread.is_alive():
        result["result"] = "Breaking algorithm takes too long."
        stop_event.set()
    
    if 'breaker' in running_threads:
        del running_threads['breaker']
    if 'breaker' in stop_events:
        del stop_events['breaker']

    return jsonify(result)

@app.route('/stop_break', methods=['POST'])
def stop_break():
    thread = running_threads.get('breaker')
    stop_event = stop_events.get('breaker')
    
    if thread and thread.is_alive() and stop_event:
        stop_event.set()
        thread.join(timeout=2)
        
        if 'breaker' in running_threads:
            del running_threads['breaker']
        if 'breaker' in stop_events:
            del stop_events['breaker']
            
        return jsonify({"message": "Breaking process stopped successfully.", "stopped": True})
    
    return jsonify({"message": "No running break process.", "stopped": False})

if __name__ == '__main__':
    print("=" * 60)
    print("🔐 RSA Encryption Demo Server")
    print("=" * 60)
    print("Server starting...")
    print("✅ Server is running!")
    print()
    print("📋 How to use:")
    print("Requirement: install flask using 'pip install flask'")
    print("   1. Open your web browser")
    print("   2. Go to: http://127.0.0.1:5000")
    print("   3. Start using the RSA demo!")
    print()
    print("Press CTRL+C to stop the server")
    print("=" * 60)

    app.run()