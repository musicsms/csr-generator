# CSR Generator

## Description

This is simple CSR Generator tool. It generates a CSR (Certificate Signing Request) for a given domain name. The generated CSR can be used to request an SSL certificate from a certificate authority.

## Usage
Get the code by git cloning the repository:
```bash
git clone https://github.com/musicsms/csr-generator.git
```

To test the tool, create virtual environment and install the required packages:
```bash
pip install -r requirements.txt
```
Run the app:
```bash
python app.py
```
Open the browser and navigate to `http://127.0.0.1:5000/`

To use on production, you can deploy the app on a server and access it via the server's IP address or domain name.
On production, recommend to use gunicorn to run the app:
```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```
Other options is running the app as container with docker/podman. You should build the image from Dockerfile first.

## License

This project is licensed under the MIT License.