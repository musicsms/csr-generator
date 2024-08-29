from flask import Flask, render_template, request
from modules.certificate import CertCSR
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for session management

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/generate_csr', methods=['POST'])
def generate_csr():
    common_name = request.form['common_name']
    alternative_names = request.form['alternative_names']
    key_type = request.form['key_type']
    if key_type == 'ecdsa':
        key_size = None  # ECDSA key size is not required
    else:
        key_size = request.form['key_size']
    passphrase_option = request.form['passphrase_option']
    if passphrase_option == 'random':
        passphrase_length = int(request.form['passphrase_length'])
        passphrase = CertCSR.generate_passphrase(passphrase_length)
    else:
        passphrase = request.form['passphrase']

    csr_data = CertCSR(
        common_name=common_name,
        alternative_names=alternative_names,
        key_size=key_size,
        key_type=key_type,
        passphrase=passphrase
    )
    output = csr_data.generate_csr()

    csr = output['csr']
    private_key = output['private_key_encrypted']
    return render_template('result.html', csr=csr, private_key=private_key, passphrase=passphrase)


if __name__ == '__main__':
    app.run(debug=True)