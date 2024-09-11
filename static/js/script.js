document.getElementById('key_type').addEventListener('change', function() {
    document.getElementById('key_size').disabled = this.value === 'ecdsa';
});

document.getElementById('ssh_key_type').addEventListener('change', function() {
    document.getElementById('ssh_key_size').disabled = this.value === 'ecdsa';
});

document.getElementById('passphrase_option').addEventListener('change', function() {
    if (this.value === 'random') {
        document.getElementById('passphrase_group').style.display = 'none';
        document.getElementById('passphrase_length_group').style.display = 'block';
        document.getElementById('passphrase').removeAttribute('required');
    } else {
        document.getElementById('passphrase_group').style.display = 'block';
        document.getElementById('passphrase_length_group').style.display = 'none';
        document.getElementById('passphrase').setAttribute('required', 'required');
    }
});