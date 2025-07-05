from flask import Flask, render_template, request, jsonify
import threading
import time
import rsa
import rsa_simple
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
    
    pub, priv = KEYGEN_ALGOS[algo](bits)

    public_key = {"e": str(pub[0]), "n": str(pub[1])}
    private_key = {"d": str(priv[0]), "n": str(priv[1])}

    return jsonify({"public": public_key, "private": private_key})

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    e, n, text = int(data['e']), int(data['n']), data['text']
    blocks = [pow(ord(c), e, n) for c in text]
    return jsonify({"result": ' '.join(map(str, blocks))})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    d, n, text = int(data['d']), int(data['n']), data['text']
    blocks = text.strip().split()
    try:
        decrypted_chars = []
        for b in blocks:
            decrypted_val = pow(int(b), d, n)
            # Check if the decrypted value is within valid Unicode range
            if 0 <= decrypted_val <= 1114111:
                decrypted_chars.append(chr(decrypted_val))
            else:
                # If value is too large, it might be corrupted or wrong key
                return jsonify({"result": f"Decryption failed: Invalid character value {decrypted_val}"})
        
        result = ''.join(decrypted_chars)
    except ValueError as e:
        return jsonify({"result": f"Decryption failed: Invalid input - {str(e)}"})
    except OverflowError as e:
        return jsonify({"result": f"Decryption failed: Number too large - {str(e)}"})
    except Exception as e:
        return jsonify({"result": "Decryption failed: " + str(e)})
    return jsonify({"result": result})

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
            
            # All breaking algorithms expect a tuple (e, n) as public_key parameter
            public_key = (e, n)
            
            # Pass the stop_event to the breaking algorithm
            private_key_tuple = BREAKING_ALGOS[algo](public_key, stop_event)
            
            end = time.time()
            
            # Check if the process was stopped
            if stop_event.is_set():
                result["result"] = "Breaking process was stopped by user."
                return
            
            if private_key_tuple and private_key_tuple[0] is not None:
                # The breaking algorithms return (d, n) where d is the private key
                d, n_returned = private_key_tuple
                result["result"] = f"Successfully broke RSA key!\nPrivate key (d, n): ({d}, {n_returned})\nTime: {end - start:.2f} sec"
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
    thread.join(timeout=300)  # 5 minutes

    if thread.is_alive():
        result["result"] = "Breaking algorithm takes too long."
        stop_event.set()  # Signal the thread to stop
    
    # Clean up
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
        # Signal the thread to stop
        stop_event.set()
        
        # Wait a bit for the thread to finish gracefully
        thread.join(timeout=2)
        
        # Clean up
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