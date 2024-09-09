from flask import Flask, render_template, request, session, redirect, url_for
from modules.certificate import CertCSR
from modules.utils import generate_passphrase
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for session management


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/submit', methods=['POST'])
def generate_csr():
    # Collect data from the form
    common_name = request.form['common_name']
    alternative_names = request.form['alternative_names']
    key_type = request.form['key_type']

    # Handle key size based on the key type
    if key_type == 'ecdsa':
        key_size = None  # ECDSA key size is not required
    else:
        key_size = request.form['key_size']

    # Handle passphrase generation or use user-provided passphrase
    passphrase_option = request.form['passphrase_option']
    if passphrase_option == 'random':
        passphrase_length = int(request.form['passphrase_length'])
        passphrase = generate_passphrase(passphrase_length)
    else:
        passphrase = request.form['passphrase']

    # Generate CSR and private key
    csr_data = CertCSR(
        common_name=common_name,
        alternative_names=alternative_names,
        key_size=key_size,
        key_type=key_type,
        passphrase=passphrase
    )
    output = csr_data.generate_csr()

    # Store the CSR result in the session
    session['csr'] = output['csr']
    session['private_key'] = output['private_key_encrypted']
    session['passphrase'] = passphrase

    # Redirect to the /generate_csr page (GET request) to avoid form re-submission
    return redirect(url_for('generate_csr_result'))


@app.route('/result', methods=['GET'])
def generate_csr_result():
    # Check if CSR data is in the session
    if 'csr' in session and 'private_key' in session and 'passphrase' in session:
        csr = session['csr']
        private_key = session['private_key']
        passphrase = session['passphrase']
        return render_template('result.html', csr=csr, private_key=private_key, passphrase=passphrase)

    # If session data is missing, redirect back to the main page
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)